#ifndef MOSQUITTO_SIGNAL_H
#define MOSQUITTO_SIGNAL_H

enum mosq_signal {
	MSIG_CONFIG_RELOAD,
	MSIG_LOG_ROTATE,
	MSIG_SHUTDOWN,
	MSIG_TREE_PRINT,
	MSIG_XTREPORT,
};

void signal_all(enum mosq_signal sig);
void send_signal(int pid, enum mosq_signal msig);

#endif
