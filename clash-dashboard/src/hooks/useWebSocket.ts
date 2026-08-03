import { useEffect, useState } from 'react';

export type ReadyState = 'CONNECTING' | 'OPEN' | 'CLOSING' | 'CLOSED';

interface UseWebSocketReturn<T> {
  lastMessage: T | null;
  readyState: ReadyState;
}

export function useWebSocket<T = unknown>(url: string | null): UseWebSocketReturn<T> {
  const [lastMessage, setLastMessage] = useState<T | null>(null);
  const [readyState, setReadyState] = useState<ReadyState>('CLOSED');

  useEffect(() => {
    let active = true;
    let socket: WebSocket | null = null;
    let retryCount = 0;
    let retryTimeout: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (!active) return;
      if (!url) {
        setReadyState('CLOSED');
        setLastMessage(null);
        return;
      }

      setReadyState('CONNECTING');
      const ws = new WebSocket(url);
      socket = ws;

      ws.onopen = () => {
        if (!active) {
          ws.close();
          return;
        }
        setReadyState('OPEN');
        retryCount = 0;
      };

      ws.onmessage = (event) => {
        if (!active) return;
        try {
          setLastMessage(JSON.parse(event.data) as T);
        } catch {
          // Ignore malformed messages and keep the connection alive.
        }
      };

      ws.onclose = () => {
        if (!active) return;
        setReadyState('CLOSED');
        socket = null;
        const delay = Math.min(1000 * 2 ** retryCount, 30000);
        retryCount += 1;
        retryTimeout = setTimeout(connect, delay);
      };

      ws.onerror = () => ws.close();
    }

    connect();

    return () => {
      active = false;
      if (retryTimeout) clearTimeout(retryTimeout);
      socket?.close();
    };
  }, [url]);

  return { lastMessage, readyState };
}
