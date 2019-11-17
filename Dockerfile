FROM node:current-alpine as react-builder
COPY ./ui /ui
WORKDIR /ui
RUN yarn && \
    yarn build

FROM mcr.microsoft.com/dotnet/core/sdk:3.0 as aspnet-builder
COPY ./backend /backend
WORKDIR /backend
RUN dotnet restore && \
    dotnet publish -c Release -o build && \
    rm build/ui/index.html
COPY --from=react-builder /ui/build /backend/build/ui

FROM mcr.microsoft.com/dotnet/core/aspnet:3.0 AS runtime
WORKDIR /app
COPY --from=aspnet-builder /backend/build /app
ENTRYPOINT ["dotnet", "PlexSSO.dll"]
EXPOSE 4200
