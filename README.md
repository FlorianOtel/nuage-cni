# _Experimental_ CNI plugin for Nuage Networks VSP 

Consists of the following components:
- CNI Agent server: RESTful api server maintaining the CNI information for containers running on the host.
- CNI Agent client library: Library with the operations supported by the CNI Agent server 
- CNI plugin per se: The CLI binary invoked by the container ochestration platform 


The CNI agent server and the CLI binary use X.509 certificates to authenticate each others and TLS encrypt the HTTP JSON transactions. For that purpose e.g. Kubernetes node certificates for `kubelet` can be (re)used, or any other suitable X.509 certificate valid for the respective host. Communication

Both the `nuage-cni-agent` server and `nuage-cni` CLI binary share the same configuration file. Sample configuration file are in the `samples` directory, together with CNI specific configuration. 

The code is _experimental_ and provided only as a use case for [Go SDK for Nuage Networks VSP](https://github.com/nuagenetworks/vspk-go/) and [Go SDK for Nuage Networks VRS](https://github.com/nuagenetworks/libvrsdk/). 

# DISCLAIMER 

This code is a developer community contribution. It is only provided **_as such_** with **_no liabilities_** whatsoever from Nuage Networks. 

In particular (but not limited to): 
- This code is not officially supported by any Nuage Networks product.
- It may be entirely replaced or removed, without any prior notice.
- It _may_ be eventually absorbed as part of a product offering, but Nuage Networks is under no committment or obligation to disclose if, how or when. 


For any questions, comments or feedback, please raise a GitHub issue.
