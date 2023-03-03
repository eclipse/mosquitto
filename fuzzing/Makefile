.PHONY: all clean

all:
	./generate_packet_corpora.py
	zip -r corpora/db_dump_seed_corpus.zip ../test/apps/db_dump/data/
	$(MAKE) -C broker $@
	$(MAKE) -C db_dump $@
	$(MAKE) -C lib $@

clean:
	-rm -rf corpora/broker corpora/client
	-rm -f corpora/broker_packet_seed_corpus.zip corpora/client_packet_seed_corpus.zip
	-rm -f corpora/db_dump_seed_corpus.zip
	$(MAKE) -C broker $@
	$(MAKE) -C db_dump $@
	$(MAKE) -C lib $@
