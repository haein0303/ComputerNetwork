#include "stdafx.h"
#include "interface_list.h"

/* Print all the available information on the given interface */
void ifprint(pcap_if_t* d)
{
	pcap_addr_t* a;

	/* Name */
	printf("%s\n", d->name);

	/* Description */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
		if (a->addr && a->addr->sa_family > 0)
			printf("\tAddress: %s\n", iptos(a->addr));
		if (a->netmask && a->netmask->sa_family > 0)
			printf("\tNetmask: %s\n", iptos(a->netmask));
		if (a->broadaddr && a->broadaddr->sa_family > 0)
			printf("\tBroadcast Address: %s\n", iptos(a->broadaddr));
		if (a->dstaddr && a->dstaddr->sa_family > 0)
			printf("\tDestination Address: %s\n", iptos(a->dstaddr));
	}
	printf("\n");
}

#define ADDR_STR_MAX 128
const char* iptos(struct sockaddr* sockaddr)
{
	static char address[ADDR_STR_MAX] = { 0 };
	int gni_error = 0;

	gni_error = getnameinfo(sockaddr,
		sizeof(struct sockaddr_storage),
		address,
		ADDR_STR_MAX,
		NULL,
		0,
		NI_NUMERICHOST);
	if (gni_error != 0)
	{
		fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gni_error));
		return "ERROR!";
	}

	return address;
}
