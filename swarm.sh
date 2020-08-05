# ensure swarm is active
docker swarm init

# log in to Docker Hub
docker login -u [USERNAME] -p [PASSWORD]

# build image locally
docker-compose build

# push image to Docker Hub repository
docker-compose push

# deploy
docker stack deploy --compose-file docker-compose.yml cs9163-unit-4

