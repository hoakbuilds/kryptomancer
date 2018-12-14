DOCKER_BUILD = docker build 
DOCKER_RUN = docker run
DOCKER_STOP = docker stop
DOCKER_RM = docker rm

build_app:
	$(DOCKER_BUILD) . -t kryptomancer

start_app:
	$(DOCKER_RUN) -d -p 5000:5000 --name kryptomancer kryptomancer -env docker

stop_backend:
	$(DOCKER_STOP) kryptomancer
	$(DOCKER_RM) kryptomancer