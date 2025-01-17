package main

import (
	"context"
	"strings"
	"time"
	"log"
	pb "github.com/containerd/containerd/api/services/containers/v1"
	pt "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
)

var Containerd *ContainerdHandler


type ContainerdHandler struct {
	conn *grpc.ClientConn

	client pb.ContainersClient

	taskClient pt.TasksClient

	containerd context.Context

	docker     context.Context

	containers map[string]context.Context
}

func NewContainerdHandler() *ContainerdHandler {

	ch := &ContainerdHandler{}
	
	conn, err := grpc.Dial("unix:///var/run/containerd/containerd.sock", grpc.WithInsecure())
	if err != nil {
		log.Println("no problem 2")
		return nil
	}

	ch.conn = conn

	ch.client = pb.NewContainersClient(ch.conn)

	ch.taskClient = pt.NewTasksClient(ch.conn)

	ch.docker = namespaces.WithNamespace(context.Background(), "moby")

	ch.containerd = namespaces.WithNamespace(context.Background(), "k8s.io")

	ch.containers = map[string]context.Context{}
	
	return ch
}

func (ch *ContainerdHandler) GetContainerInfo(ctx context.Context, containerID string) (Container, error) {
	var container Container
	req := pb.GetContainerRequest{ID: containerID}
	res, err := ch.client.Get(ctx, &req)
	if err != nil {
		return container, err
	}
	container.ContainerID = res.Container.ID
	container.ContainerName = res.Container.ID

	taskReq := pt.ListPidsRequest{ContainerID: container.ContainerID}
	if taskRes, err := ch.taskClient.ListPids(ctx, &taskReq); err == nil {
		if len(taskRes.Processes) == 0 {
			return container, err
		}

		pid := uint32(taskRes.Processes[0].Pid)
		container.ContainerPID = pid
	}

	return container, err
}

func (ch *ContainerdHandler) GetContainerdContainers() map[string]context.Context {
	containers := map[string]context.Context{}

	req := pb.ListContainersRequest{}

	if containerList, err := ch.client.List(ch.docker, &req); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.docker
		}
	}

	if containerList, err := ch.client.List(ch.containerd, &req); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.containerd
		}
	}

	

	return containers
}

func (ch *ContainerdHandler) GetNewContainerdContainers(containers map[string]context.Context) map[string]context.Context {
	newContainers := map[string]context.Context{}
	for activeContainerID, context := range containers {
		if _, ok := ch.containers[activeContainerID]; !ok {
			newContainers[activeContainerID] = context
		}
	}

	return newContainers
}

func (ch *ContainerdHandler) UpdateContainerdContainer(ctx context.Context, containerID, action string) bool {
	// check if Containerd exists
	if Containerd == nil {
		return false
	}
	if action == "start" {
		// get container information from containerd client
		container, err := ch.GetContainerInfo(ctx, containerID)
		if err != nil {
			return false
		}

		if container.ContainerID == "" {
			log.Println("container.ContainerID == \"\"")
			return false
		}
		if strings.Contains(container.ContainerComm, "pause") {
			return false
		}
		// if _, ok := ch.containers[container.ContainerID]; !ok {
		ch.containers[container.ContainerID] = ctx
		// } else {
		// 	log.Println("ok := ch.containers[containerID] else")
		// 	return false
		// }
		log.Println("Pinning!!!!!!!!!!")
		PinMap(container.ContainerPID, container.ContainerName)

		log.Printf("Detected a new container (%s/%s)", container.MicroserviceName, container.ContainerName)

	} else if action == "destroy" {
		container, err := ch.GetContainerInfo(ctx, containerID)
		if err != nil {
			return false
		}

		if container.ContainerID == "" {
			return false
		}

		UnpinMap(container.ContainerPID, container.ContainerName)
		delete(ch.containers, containerID)
		if strings.HasPrefix(container.ContainerName, "k8s_POD") {
			return false
		}
	}

	return true
}

func (ch *ContainerdHandler) GetDeletedContainerdContainers(containers map[string]context.Context) map[string]context.Context {
	deletedContainers := map[string]context.Context{}

	for globalContainerID := range ch.containers {
		if _, ok := containers[globalContainerID]; !ok {
			deletedContainers[globalContainerID] = context.TODO()
			delete(ch.containers, globalContainerID)
		}
	}

	ch.containers = containers

	return deletedContainers
}

// MonitorContainerdEvents Function
func MonitorContainerdEvents() {
	defer log.Println("err with MonitorDockerEvent")

	Containerd = NewContainerdHandler()

	// check if Containerd exists
	if Containerd == nil {
		log.Println("Containerd == nil")
		return
	}

	for {
		containers := Containerd.GetContainerdContainers()
		
		invalidContainers := []string{}

		newContainers := Containerd.GetNewContainerdContainers(containers)

		deletedContainers := Containerd.GetDeletedContainerdContainers(containers)

		if len(newContainers) > 0 {
			for containerID, context := range newContainers {
				if !Containerd.UpdateContainerdContainer(context, containerID, "start") {
					invalidContainers = append(invalidContainers, containerID)
				}
			}
		}

		for _, invalidContainerID := range invalidContainers {
			delete(Containerd.containers, invalidContainerID)
		}

		if len(deletedContainers) > 0 {
			for containerID, context := range deletedContainers {
				Containerd.UpdateContainerdContainer(context, containerID, "destroy")
			}
		}

		time.Sleep(time.Millisecond * 500)
	}
}

func containerdDaemon() {
	log.Println("Waiting for the response")

	go MonitorContainerdEvents()
}