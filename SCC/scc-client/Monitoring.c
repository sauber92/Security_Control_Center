#include <stdio.h>
#include <stdlib.h>

int main() {
	system("tail -1 /var/log/auth.log > login.log");
	system("tail -1 /var/log/syslog | grep packet > packet.log");

	FILE *login_fp = fopen("login.log", "r");
	FILE *packet_fp = fopen("packet.log", "r");

	char login_buf[500] = {0, };
	char login_buf2[500] = {0, };

	char packet_buf[500] = {0, };
	char packet_buf2[500] = {0, };

	fread(login_buf, sizeof(login_buf), 1, login_fp);
	snprintf(login_buf2, sizeof(login_buf2), "mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e 'insert into login_monitoring (`id`, `login_log`) values (1001, \"%s\")'", login_buf); 
	
	fread(packet_buf, sizeof(packet_buf), 1, packet_fp);
	snprintf(packet_buf2, sizeof(packet_buf2), "mysql -h '163.180.118.193' -uroot -'proot' scc --ssl -e 'insert into packet_monitoring (`id`, `packet_log`) values (1001, \"%s\")'", packet_buf); 

	system(login_buf2);
	system(packet_buf2);

	fclose(login_fp);
	fclose(packet_fp);

	return 0;
}
