@echo off

set dockerid="%pintos%\.container-id"

if not exist "%pintos%\.container-id" (docker create -t -i -v "%pintos%":/pintos -v "%pintos%\container":/host --cidfile %dockerid% "gbenm/pintos:latest")

set /p dockerid=<%dockerid%

if "%1"=="stop" (docker stop %dockerid%) else (docker start %dockerid% & docker exec -u pintos -it %dockerid% bash)

