#include <stdio.h>

#include "Secure_boot.h"
#include "Secure_Firmware_Update.h"
#include "Attestation.h"

int main(void)
{
	Secure_Boot_Daemon();
	Update_Daemon(sbio);
	attestation_Daemon(sbio);

	return 0;
}