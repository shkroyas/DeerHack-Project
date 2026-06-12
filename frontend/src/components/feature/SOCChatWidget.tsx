import React, { useState } from 'react';
import { Send, Sparkles, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  challenge?: string;
  timestamp: Date;
}

const QUICK_QUESTIONS = [
  { id: 'c1', label: 'C1', question: 'Why is this a zero-day threat?', color: 'challenge-badge-c1' },
  { id: 'c2', label: 'C2', question: 'Why no false positive here?', color: 'challenge-badge-c2' },
  { id: 'c3', label: 'C3', question: 'How many alerts suppressed?', color: 'challenge-badge-c3' },
  { id: 'c4', label: 'C4', question: 'How detect encrypted TLS?', color: 'challenge-badge-c4' },
];

export const SOCChatWidget: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '0',
      role: 'assistant',
      content: 'I\'m BankSentinel SOC AI. Ask me about any alert or detection challenge. Try a quick question below.',
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const sendMessage = async (question: string) => {
    if (!question.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: 'user',
      content: question,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'}/soc/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question }),
      });

      if (res.ok) {
        const data = await res.json();
        setMessages((prev) => [
          ...prev,
          {
            id: (Date.now() + 1).toString(),
            role: 'assistant',
            content: data.answer,
            challenge: data.challenge,
            timestamp: new Date(),
          },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: (Date.now() + 1).toString(),
            role: 'assistant',
            content: 'Sorry, I couldn\'t process that request. The backend may not be running.',
            timestamp: new Date(),
          },
        ]);
      }
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: 'Connection error. Make sure the BankSentinel API is running on port 8000.',
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="glass-panel p-4 flex flex-col h-full" style={{ minHeight: '400px' }}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Sparkles size={14} className="text-challenge-c3" />
          <span className="text-sm font-semibold text-white">SOC Assistant</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="challenge-badge challenge-badge-c3">C3</span>
          <Link to="/soc" className="text-text-muted hover:text-text-primary transition-colors">
            <ExternalLink size={12} />
          </Link>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-3 mb-3 min-h-0">
        {messages.slice(-5).map((msg) => (
          <div
            key={msg.id}
            className={`${msg.role === 'user' ? 'chat-bubble-user ml-8' : 'chat-bubble-ai mr-4'} animate-fade-up`}
          >
            <div className="text-xs text-text-secondary whitespace-pre-wrap leading-relaxed">
              {msg.content.length > 200 ? msg.content.slice(0, 200) + '...' : msg.content}
            </div>
            {msg.challenge && (
              <span className={`challenge-badge challenge-badge-${msg.challenge.toLowerCase()} mt-2 inline-block`}>
                {msg.challenge}
              </span>
            )}
          </div>
        ))}
        {isLoading && (
          <div className="chat-bubble-ai mr-4">
            <div className="typing-indicator flex gap-1">
              <span /><span /><span />
            </div>
          </div>
        )}
      </div>

      {/* Quick Questions */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        {QUICK_QUESTIONS.map((q) => (
          <button
            key={q.id}
            onClick={() => sendMessage(q.question)}
            disabled={isLoading}
            className="flex items-center gap-1 px-2 py-1 rounded-md text-[10px] bg-background-elevated hover:bg-background-border transition-colors text-text-secondary hover:text-text-primary disabled:opacity-40"
          >
            <span className={`challenge-badge ${q.color}`} style={{ fontSize: '8px', padding: '0 3px' }}>{q.label}</span>
            {q.question}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && sendMessage(input)}
          placeholder="Ask about any alert..."
          className="input-dark flex-1 text-xs"
          disabled={isLoading}
        />
        <button
          onClick={() => sendMessage(input)}
          disabled={isLoading || !input.trim()}
          className="btn-primary px-3 py-2 disabled:opacity-40"
        >
          <Send size={12} />
        </button>
      </div>
    </div>
  );
};
