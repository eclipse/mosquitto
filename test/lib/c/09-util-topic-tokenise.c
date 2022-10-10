#include <stdio.h>
#include <string.h>
#include <mosquitto.h>

static void print_error(const char *topic, char **topics, int topic_count)
{
	int i;
	printf("TOPIC: %s\n", topic);
	printf("TOKENS: ");
	for(i=0; i<topic_count; i++){
		printf("%s", topics[i]);
		if(i+1<topic_count){
			printf("/");
		}
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	char **topics;
	int topic_count;

	(void)argc;
	(void)argv;

	if(mosquitto_sub_topic_tokenise("topic", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 1 || strcmp(topics[0], "topic")){
		print_error("topic", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	if(mosquitto_sub_topic_tokenise("a/deep/topic/hierarchy", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 4
			|| strcmp(topics[0], "a")
			|| strcmp(topics[1], "deep")
			|| strcmp(topics[2], "topic")
			|| strcmp(topics[3], "hierarchy")){
		print_error("a/deep/topic/hierarchy", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	if(mosquitto_sub_topic_tokenise("/a/deep/topic/hierarchy", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 5
			|| topics[0]
			|| strcmp(topics[1], "a")
			|| strcmp(topics[2], "deep")
			|| strcmp(topics[3], "topic")
			|| strcmp(topics[4], "hierarchy")){
		print_error("/a/deep/topic/hierarchy", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	if(mosquitto_sub_topic_tokenise("a/b/c", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 3
			|| strcmp(topics[0], "a")
			|| strcmp(topics[1], "b")
			|| strcmp(topics[2], "c")){
		print_error("a/b/c", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	if(mosquitto_sub_topic_tokenise("/a/b/c", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 4
			|| topics[0]
			|| strcmp(topics[1], "a")
			|| strcmp(topics[2], "b")
			|| strcmp(topics[3], "c")){
		print_error("/a/b/c", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	if(mosquitto_sub_topic_tokenise("a///hierarchy", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 4
			|| strcmp(topics[0], "a")
			|| topics[1]
			|| topics[2]
			|| strcmp(topics[3], "hierarchy")){
		print_error("a///hierarchy", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	if(mosquitto_sub_topic_tokenise("/a///hierarchy", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 5
			|| topics[0]
			|| strcmp(topics[1], "a")
			|| topics[2]
			|| topics[3]
			|| strcmp(topics[4], "hierarchy")){
		print_error("/a///hierarchy", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	if(mosquitto_sub_topic_tokenise("/a///hierarchy/", &topics, &topic_count)){
		printf("Out of memory.\n");
		return 1;
	}
	if(topic_count != 6
			|| topics[0]
			|| strcmp(topics[1], "a")
			|| topics[2]
			|| topics[3]
			|| strcmp(topics[4], "hierarchy")
			|| topics[3]){
		print_error("/a///hierarchy/", topics, topic_count);
		return 1;
	}
	mosquitto_sub_topic_tokens_free(&topics, topic_count);

	return 0;
}

