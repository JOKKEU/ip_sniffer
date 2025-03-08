#include "ip_sniffer.h"


int main(int argc, char** argv)
{

	if (sniffer(argc, argv) != 0) {return EXIT_FAILURE;}
	return EXIT_SUCCESS;
}
