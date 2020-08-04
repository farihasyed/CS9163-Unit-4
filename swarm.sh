docker swarm init
# docker login -u [username] -p [password]
docker-compose build
docker-compose push
docker stack deploy --compose-file docker-compose.yml cs9163-unit-4

