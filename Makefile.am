bin_PROGRAMS = planarmqtt 
planarmqtt_SOURCES = main.c
planarmqtt_CFLAGS = -Wall
planarmqtt_LDFLAGS = 
planarmqtt_LDADD = -lm

planarmqttbindir=$(bindir)

install-exec-hook:
	cp utils/planarmqtt.sh $(planarmqttbindir)/
	chmod 777 $(planar-mqttbindir)/planarmqtt.sh

uinstall-hook:
	rm $(planarmqttbindir)/planarmqtt.sh

