.PHONY: build img

IMGNAME := rpc_fuzzing_tools

all : build start

build:
	docker build -t $(IMGNAME):latest -f Dockerfile .

start:
	docker run --rm -it $(IMGNAME)

shell:
	docker exec -it $(shell docker ps | grep $(IMGNAME) | awk '{split($$0,a," "); print a[1]}') bash
