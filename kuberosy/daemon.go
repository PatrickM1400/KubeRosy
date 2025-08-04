package main

import (
    "strings"
    "log"
	"encoding/binary"
	"github.com/cilium/ebpf"
    "github.com/docker/docker/api/types/events"
)

const (
	comm_pid_map_path        = "/sys/fs/bpf/daemon_map/containerID_PID_map"
)


type ContainerDaemon struct {
    EventChan <-chan events.Message

    EventLogs []DockerEvent

    Containers     map[string]Container
}

func NewContainerDaemon() *ContainerDaemon {
    cm := new(ContainerDaemon)

    cm.EventChan = Docker.GetEventChannel()
    cm.EventLogs = []DockerEvent{}

    cm.Containers = map[string]Container{}

    return cm
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
	
    for {
		select {

		case msg, valid := <-cm.EventChan:
			if !valid {
				continue
			}

			// if message type is container
			if msg.Type == "container" {
				cm.UpdateContainer(msg.ID, string(msg.Action))
			}

			// build event log and push it to the list
			cm.EventLogs = append(cm.EventLogs, DockerEvent{
				ContainerID:   msg.Actor.ID,
				ContainerName: msg.Actor.Attributes["name"],
				Type:          string(msg.Type),
				Action:        string(msg.Action),
				RawEvent:      msg,
			})
			log.Printf("Container ID : ", msg.Actor.ID, "\nType : ", msg.Type,"\nAction : ", msg.Action,"\nContainer name : ", msg.Actor.Attributes["name"], "\nContainer PID : ", cm.Containers[msg.Actor.ID].ContainerPID, "\n")
		}
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

func PinMap(pid uint32, comm string){
	bpf_comm_Map, err := ebpf.LoadPinnedMap(comm_pid_map_path, nil)
	if err != nil || bpf_comm_Map == nil {
		log.Fatalf("Error loading pinned map: %v", err)
	}
	defer bpf_comm_Map.Close()

	var pidBytes [4]byte
	var keyBytes [16]byte

	copy(keyBytes[:], comm)
    binary.LittleEndian.PutUint32(pidBytes[:], pid)
	

	if  pid != 0 {
		err = bpf_comm_Map.Update(keyBytes, pidBytes, ebpf.UpdateAny)
		if err != nil{
			log.Print("could not put element to map: %s", err)
		}
	}
}

func UnpinMap(pid uint32, comm string){
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
	if err != nil{
        log.Print("could not delete element : %s", err)
    }
}


func Daemon() {
	
    cm := NewContainerDaemon()

    log.Println("Waiting for the response for Daemon")

    go cm.MonitorDockerEvent()

}