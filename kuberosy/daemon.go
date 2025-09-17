package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/docker/docker/api/types/events"
)

const (
	comm_pid_map_path = "/sys/fs/bpf/daemon_map/containerID_PID_map"
	monitoring_map    = "/sys/fs/bpf/daemon_map/monitoring_map"
	policy_map        = "/sys/fs/bpf/daemon_map/policy_map"
)

type pid_mount_ns struct {
	mountns uint64
	pidns   uint64
}

type AllowedSyscalls struct {
	AllowedSyscalls []int
}

// Global variable for default seccomp profile used on container initilization
var DefaultProfile [8]uint64

type ContainerDaemon struct {
	EventChan <-chan events.Message

	EventLogs []DockerEvent

	Containers map[string]Container
}

func NewContainerDaemon() *ContainerDaemon {
	cm := new(ContainerDaemon)

	cm.EventChan = Docker.GetEventChannel()
	cm.EventLogs = []DockerEvent{}

	cm.Containers = map[string]Container{}

	return cm
}

func init() {

	fileName := "containerEventLog"
	logFile, err := os.Create(fileName)
	if err != nil {
		log.Printf("Failed to create containerEventLog: %s", err)
	}

	log.SetOutput(logFile)

	// Generate default seccomp allow policy
	syscallFilename := "init_profile_allowed.json"
	content, err := os.ReadFile(syscallFilename)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}

	var payload AllowedSyscalls
	err = json.Unmarshal(content, &payload)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	len := len(payload.AllowedSyscalls)
	for i := 0; i < len; i++ {
		syscall_num := payload.AllowedSyscalls[i]
		idx := syscall_num / 64
		mask := syscall_num % 64

		var tmp uint64 = DefaultProfile[idx]
		tmp = tmp | (1 << mask)
		DefaultProfile[idx] = tmp
	}
	// fmt.Println(DefaultProfile)
}

// getNamespaceID reads the symbolic link for a given namespace type and parses the ID.
func getNamespaceID(pid int, nsType string) uint64 {
	// Construct the path to the namespace symbolic link
	nsPath := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)

	// Read the symbolic link
	link, err := os.Readlink(nsPath)
	if err != nil {
		log.Fatalf("error reading namespace link %s: %w", nsPath, err)
	}

	// The link format is "nstype:[inode_number]". We parse the inode number.
	var nsID uint64
	// Example link string: "pid:[4026531836]"
	cutLink, found := strings.CutPrefix(link, nsType)
	if !found {
		log.Fatalf("Unexpected link format found: '%s", link)
	}

	scanned, err := fmt.Sscanf(cutLink, ":[%d]", &nsID)
	if err != nil || scanned != 1 {
		log.Fatalf("error parsing namespace ID from string '%s': %w", link, err)
	}

	return nsID
}

func (cm *ContainerDaemon) UpdateContainerFromList() {
	containerlist, err := Docker.GetContainerList()
	if err != nil {
		log.Fatal(err)
		return
	}

	for _, container := range containerlist {
		name := strings.TrimLeft(container.Names[0], "/")

		// skip paused containers in k8s
		if strings.HasPrefix(name, "k8s_POD") {
			continue
		}

		if _, ok := cm.Containers[container.ID]; !ok {
			cm.UpdateContainer(container.ID, "start")
		}
	}
}

func (cm *ContainerDaemon) MonitorDockerEvent() {
	defer log.Println("err with MonitorDockerEvent")

	cm.UpdateContainerFromList()

	for msg := range cm.EventChan {
		// if message type is container
		if msg.Type == "container" {
			cm.UpdateContainer(msg.Actor.ID, string(msg.Action))
		}

		// build event log and push it to the list
		cm.EventLogs = append(cm.EventLogs, DockerEvent{
			ContainerID:   msg.Actor.ID,
			ContainerName: msg.Actor.Attributes["name"],
			Type:          string(msg.Type),
			Action:        string(msg.Action),
			RawEvent:      msg,
		})
		log.Print("Container ID : ", msg.Actor.ID, "\nType : ", msg.Type, "\nAction : ", msg.Action, "\nContainer name : ", msg.Actor.Attributes["name"], "\nContainer PID : ", cm.Containers[msg.Actor.ID].ContainerPID, "\n\n")
	}
}

func (cm *ContainerDaemon) UpdateContainer(containerID, action string) {
	defer log.Println("UpdateContainer finished")

	container := Container{}

	if action == "start" {
		var err error

		// get container information from docker client
		container, err = Docker.GetContainerInfo(containerID)
		if err != nil {
			log.Fatal(err)
			return
		}

		if container.ContainerID == "" {
			return
		}

		// skip paused containers in k8s
		if strings.HasPrefix(container.ContainerName, "k8s_POD") {
			return
		}

		// add container to containers map
		if _, ok := cm.Containers[containerID]; !ok {
			cm.Containers[containerID] = container
		} else {
			return
		}

		PinMap(container.ContainerPID, container.ContainerID)

		log.Printf("Detected a new container (%s/%s)", container.MicroserviceName, container.ContainerName)

		context := context.Background()
		json, err := Docker.DockerClient.ContainerInspect(context, container.ContainerID)
		if err != nil {
			log.Fatal(err)
			return
		}
		log.Printf("Container PID: %d", json.State.Pid)
		hostPid := json.State.Pid

		if hostPid != 0 {
			pidNS_ID := getNamespaceID(hostPid, "pid")
			mntNS_ID := getNamespaceID(hostPid, "mnt")

			log.Printf("Process Namespace ID: %d\n", pidNS_ID)
			log.Printf("Mount Namespace ID:   %d\n", mntNS_ID)

			// Set monitoring_map so kernel program knows process is runnning in container
			bpf_monitoring_map, err := ebpf.LoadPinnedMap(monitoring_map, nil)
			if err != nil || bpf_monitoring_map == nil {
				log.Fatalf("Error loading pinned map: %v", err)
			}
			defer bpf_monitoring_map.Close()

			ns := pid_mount_ns{pidns: pidNS_ID, mountns: mntNS_ID}
			var val uint32 = 1

			err = bpf_monitoring_map.Update(ns, val, ebpf.UpdateAny)
			if err != nil {
				log.Printf("could not put element to map: %s", err)
			}

			// Load default seccomp syscall allow list profile upon container init
			bpf_policy_map, err := ebpf.LoadPinnedMap(policy_map, nil)
			if err != nil || bpf_monitoring_map == nil {
				log.Fatalf("Error loading pinned map: %v", err)
			}
			defer bpf_monitoring_map.Close()

			err = bpf_policy_map.Update(ns, DefaultProfile, ebpf.UpdateAny)
			if err != nil {
				log.Printf("could not put element to map: %s", err)
			}

		}

	} else if action == "stop" || action == "destroy" {
		// case 1: kill -> die -> stop
		// case 2: kill -> die -> destroy
		// case 3: destroy

		val, ok := cm.Containers[containerID]
		if !ok {
			return
		}

		container = val
		UnpinMap(container.ContainerPID, container.ContainerID)
		delete(cm.Containers, containerID)

		if strings.HasPrefix(container.ContainerName, "k8s_POD") {
			return
		}

		log.Printf("Detected a removed container (%s/%s)", container.MicroserviceName, container.ContainerName)
	}

}

func PinMap(pid uint32, comm string) {
	bpf_comm_Map, err := ebpf.LoadPinnedMap(comm_pid_map_path, nil)
	if err != nil || bpf_comm_Map == nil {
		log.Fatalf("Error loading pinned map: %v", err)
	}
	defer bpf_comm_Map.Close()

	var pidBytes [4]byte
	var keyBytes [16]byte

	copy(keyBytes[:], comm)
	binary.LittleEndian.PutUint32(pidBytes[:], pid)

	if pid != 0 {
		err = bpf_comm_Map.Update(keyBytes, pidBytes, ebpf.UpdateAny)
		if err != nil {
			log.Print("could not put element to map: %s", err)
		}
	}
}

func UnpinMap(pid uint32, comm string) {
	bpf_comm_Map, err := ebpf.LoadPinnedMap(comm_pid_map_path, nil)
	if err != nil || bpf_comm_Map == nil {
		log.Print("Error loading pinned map: %v", err)
	}
	defer bpf_comm_Map.Close()

	var keyBytes [16]byte
	copy(keyBytes[:], comm)
	var pidBytes [4]byte
	binary.LittleEndian.PutUint32(pidBytes[:], pid)

	err = bpf_comm_Map.Delete(keyBytes)
	if err != nil {
		log.Print("could not delete element : %s", err)
	}
}

func Daemon() {

	cm := NewContainerDaemon()

	log.Println("Waiting for the response for Daemon")

	go cm.MonitorDockerEvent()

}
