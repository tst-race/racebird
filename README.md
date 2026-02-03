# Racebird (Raceboat Plugin)

The Racebird plugin wraps the Lyrebird pluggable transport to enable use of Obfs4 with Raceboat.

## Building

Racebird uses a docker-based build to build the plugin:

```
./build_artifacts_in_docker_image.sh
```

## Testing

Racebird has a simple dockerized interactive integration test using racebird to connect a netcat client and server.

(Ensure the plugin has been built, as above)


This test will use three terminals, one to run the docker containers, one to run the netcat server, and one to run the netcat client.

### Terminal 1: Docker:
```
cd scripts
./setup.sh
docker-compose up
```

### Terminal 2: Netcat Server:
```
cd scripts
./server.sh
```

### Terminal 3: Netcat Client:
```
cd scripts
./client.sh
```

The server terminal should now contain "hello", sent by the raceboat client. Now either the client or server terminal can be typed in, and the message should appear on the other side.