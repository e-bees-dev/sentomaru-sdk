# Item 16 / P-1: the laboratory host of the device round, as a container for the lab device (its dotnet is 10.0.114, and the
# repository's global.json pins 10.0.112 with rollForward disabled; no 10.0.112 SDK image exists, so the pin is dropped here).
# Build from the repository root:  docker build -f integrations/samples/aspnetcore-rasp-lab-host/Dockerfile -t rasp-lab-host .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY integrations/aspnetcore ./integrations/aspnetcore
COPY integrations/samples/aspnetcore-third-party ./integrations/samples/aspnetcore-third-party
COPY integrations/samples/aspnetcore-rasp-lab-host ./integrations/samples/aspnetcore-rasp-lab-host
RUN dotnet publish integrations/samples/aspnetcore-rasp-lab-host/RaspLabHost.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
# Development on purpose: the host refuses to start in any other environment. Lab network only, for the window of the round.
ENV ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS=https://+:8443
EXPOSE 8443
ENTRYPOINT ["dotnet", "RaspLabHost.dll"]
