package main

import (
	"errors"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
)

var Docker *DockerHandler

func init() {
	Docker = NewDockerHandler()
}

// ==================== //
// == Docker Handler == //
// ==================== //

type DockerHandler struct {
	DockerClient *client.Client
}

func NewDockerHandler() *DockerHandler {
	docker := &DockerHandler{}
	docker.DockerClient, _ = client.NewEnvClient()

	return docker
}

// ==================== //
// == Container Info == //
// ==================== //

func (dh *DockerHandler) GetContainerList() ([]types.Container, error) {
	if dh.DockerClient == nil {
		return nil, errors.New("docker client is nil")
	}

	list, err := dh.DockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (dh *DockerHandler) GetEventChannel() <-chan events.Message {
	if dh.DockerClient != nil {
		event, _ := dh.DockerClient.Events(context.Background(), types.EventsOptions{})
		return event
	}

	return nil
}

func (dh *DockerHandler) GetContainerInfo(containerid string) (Container, error) {
	if dh.DockerClient == nil {
		return Container{}, errors.New("docker client is nil")
	}

	NOT_IN_MICROSERVICE := "__independent_container__"
	if val, ok := os.LookupEnv("NOT_IN_MICROSERVICE"); ok {
		NOT_IN_MICROSERVICE = val
	}

	inspect, err := dh.DockerClient.ContainerInspect(context.Background(), containerid)
	if err != nil {
		return Container{}, err
	}
	

	
	
	container := Container{}

	// == container base == //

	container.ContainerID = inspect.ID
	container.ContainerName = strings.TrimLeft(inspect.Name, "/")
	container.ContainerPID = uint32(inspect.State.Pid)

	container.Status = inspect.State.Status

	containerLabels := inspect.Config.Labels
	if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok { // kubernetes
		if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
			container.MicroserviceName = val
		} else {
			container.MicroserviceName = NOT_IN_MICROSERVICE
		}
	} else if _, ok := containerLabels["com.docker.compose.project"]; ok { // docker-compose
		if val, ok := containerLabels["com.docker.compose.project"]; ok {
			container.MicroserviceName = val
		} else {
			container.MicroserviceName = NOT_IN_MICROSERVICE
		}
		
	} else { // docker
		container.MicroserviceName = NOT_IN_MICROSERVICE
	}
	
	// == //

	return container, nil
}
