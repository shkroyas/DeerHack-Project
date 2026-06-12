import { io, Socket } from 'socket.io-client';
import { getConfig } from './config';

let socket: Socket | null = null;

export const connectSocket = () => {
  const { wsUrl } = getConfig();
  if (!socket) {
    socket = io(wsUrl, { transports: ['websocket'], autoConnect: false });
  }
  if (!socket.connected) socket.connect();
  return socket;
};

export const getSocket = () => socket;

export const disconnectSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
};
