# Pantavisor

## What is Pantavisor? 
Pantavisor is the easiest way to build and manage embedded Linux projects with lightweight containers. Put your Linux distribution or custom-made firmware and userland into containers and get all of the benefits of portable containerized lifecycle management without needing to replace your distribution. 

Pantavisor is the Linux device init system that turns the runtime into a set of containerized microservices. It is not a container engine but rather a framework for assembling and managing containerized building blocks for firmware and applications. Pantavisor provides a simple way to deploy and atomically manage your containerized embedded firmware and apps across millions of devices in a reproducible manner. 

### Meets the requirements of low-spec devices 
To ensure it can cover the low-spec end of the market, Pantavisor brings full container functionality into a single binary to keeps its size as small as possible. Depending on the software functions that are built into the container, the size can vary, but the average for a fully functional system puts the Pantavisor binary at around 1mg (as a compressed initial ramdisk).

Pantavisor takes advantage of pure Linux container technology. It implements parts of the LXC suite as a library that wraps around the basic building blocks of containers. Because LXC is a pure C project, the overall footprint of Pantavisor is very small.

### Build your embedded system with containerized building blocks
With a containerized system, you can mix and match components from different distros to build your system and update and maintain customizations without replacing your distro or the entire board.

<img src="https://pantavisor.io/images/pantavisor-linux.svg" width="200"/>

In a Pantavisor-enabled device, each application or service is defined as a container, including all of the associated objects that are needed to start them. In Pantavisor this includes:

* **Board Support Packages (BSPs)**: kernel, modules, and firmware. 
* **System Middleware Containers**: you can choose to package your monolithic distro middleware in one or build your middleware in more fine-grained units. 
* **Apps**: Linux or Docker containers.
* **Configuration**: system level configurations

In the case of a multi-service system, there can be definitions of these that make up the full running system. This is what we refer to as the Pantavisor State Format. This state is declarative and is in JSON format. It is managed via the Pantavisor CLI and kept in our SaaS Pantacor Hub or managed locally on your device with the system utilities [Pantabox](https://docs.pantahub.com/before-you-begin/#pvr-cli-vs-pantabox-utilities). 

## Pantacor Hub and Pantavisor
Pantacor Hub is the open source SaaS that manages app and device state in the cloud. You can think of it as a cross between an image sharing repository, a device system revision repository and a deployment platform. The hub allows you to share images and device data between team members or other users. It also manages the atomic revisions of the device state and also deploys them over the air across device fleets. In addition, you can use it to view logs, troubleshoot and configure devices as well as edit application, and user meta-data.

## How to Get Started
This is the quickest way to get to know Pantavisor:

If you have a device like a Raspberry Pi, you can download a pre-built image for Raspberry Pi and several other device types that come with Pantavisor installed: 

* **Start here** ->  [Download a pre-built image with Pantavisor](https://pantavisor.io/#download)
* [Install Pantavisor onto your Embedded Linux Device](https://pantavisor.io/guides/getting_started/)

After you've downloaded and flashed your device with Pantavisor, try out a tutorial: 
* [Install and configure NGINX from Docker Hub](https://pantavisor.io/guides/install-from-docker-hub/)

* For an overview of Pantavisor see:  [Working with Pantavisor](https://docs.pantahub.com/before-you-begin/)

## Getting help and support
We're a friendly and helpful community and welcome questions, and any feedback you may have. 

- Pantavisor Discussion Forum:
     - [Pantavisor Community Forum](https://community.pantavisor.io)

- Docs:
     - [Pantavisor Architecture](https://docs.pantahub.com/pantavisor-architecture/)
     - [Getting Started with Pantavisor](https://docs.pantahub.com/before-you-begin/)
     - [Getting Started with Pantavisor on Raspberry Pi](https://docs.pantahub.com/get-started/#getting-started-on-a-raspberry-pi)
     - [Frequently Asked Questions](https://pantavisor.io/guides/faq/)


## License
Pantavisor applies the [MIT license](LICENSE) with copyright.  


