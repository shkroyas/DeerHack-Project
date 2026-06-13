import { getConfig } from './config';

export type EventHandler = (data: any) => void; // eslint-disable-line @typescript-eslint/no-explicit-any

class SocketWrapper {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private readonly MAX_RECONNECT_ATTEMPTS = 5;
  private readonly RECONNECT_DELAY_MS = 3000;
  private listeners: Record<string, EventHandler[]> = {};

  connect() {
    const { wsUrl } = getConfig();
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      this.ws = new WebSocket(`${wsUrl}/ws/alerts`);

      this.ws.onopen = () => {
        console.log('[WS] Connected to alert stream');
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type) {
            this.emit(message.type, message.data || message);
            if (message.type === 'alert') {
              this.emit('alert:new', message.data);
            }
          }
        } catch (e) {
          console.error('[WS] Failed to parse message:', e);
        }
      };

      this.ws.onerror = (error) => {
        console.error('[WS] Connection error:', error);
      };

      this.ws.onclose = () => {
        console.log('[WS] Disconnected, attempting reconnect...');
        this.ws = null;
        if (this.reconnectAttempts < this.MAX_RECONNECT_ATTEMPTS) {
          this.reconnectAttempts++;
          setTimeout(() => this.connect(), this.RECONNECT_DELAY_MS);
        }
      };
    } catch (error) {
      console.error('[WS] Failed to create WebSocket:', error);
    }
  }

  disconnect() {
    // Only disconnect if no listeners remain
    const totalListeners = Object.values(this.listeners).reduce((acc, arr) => acc + arr.length, 0);
    if (this.ws && totalListeners === 0) {
      this.ws.close();
      this.ws = null;
    }
  }

  on(event: string, handler: EventHandler) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event]?.push(handler);
  }

  off(event: string, handler: EventHandler) {
    if (!this.listeners[event]) return;
    this.listeners[event] = this.listeners[event]?.filter(h => h !== handler) || [];
  }

  emit(event: string, payload: any): void { // eslint-disable-line @typescript-eslint/no-explicit-any
    if (!this.listeners[event]) return;
    this.listeners[event]?.forEach(handler => handler(payload));
  }

  send(message: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }
}

const socketInstance = new SocketWrapper();

export const connectSocket = () => {
  return socketInstance;
};

export const getSocket = () => socketInstance;

export const disconnectSocket = () => {
  socketInstance.disconnect();
};

export const sendSocketMessage = (message: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
  socketInstance.send(message);
};

export const emitSocketEvent = (event: string, payload: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
  socketInstance.emit(event, payload);
};
