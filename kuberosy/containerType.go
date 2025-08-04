package main

import "github.com/docker/docker/api/types/events"
// Container Structure
type Container struct {
	ContainerID   string `json:"container_id" bson:"container_id"`
	ContainerName string `json:"container_name" bson:"container_name"`
	ContainerPID  uint32    `json:"container_pid" bson:"container_pid"`
	ContainerComm string	`json:"container_comm" bson:"container_comm"`
	Status string `json:"status" bson:"status"`
	MicroserviceName   string `json:"microservice_name" bson:"microservice_name"`
}

type DockerEvent struct {

	ContainerID   string `json:"container_id" bson:"container_id"`
	ContainerName string `json:"container_name" bson:"container_name"`

	Type   string `json:"type" bson:"type"`
	Action string `json:"action" bson:"action"`

	RawEvent events.Message `json:"raw_event" bson:"raw_event"`
}

type queue struct {
	array[1024] uint32
	front uint32
	rear uint32
}