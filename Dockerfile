FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY ["package.json", "package-lock.json", "./"]
RUN npm install --omit=dev
COPY src ./src
COPY index.js .
COPY CLI.js .
COPY manage.sh ./manage
RUN chmod +x ./manage

EXPOSE 2999
USER 1000
CMD ["node", "index.js"]