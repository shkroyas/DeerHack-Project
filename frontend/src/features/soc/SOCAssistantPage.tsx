import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, Send, Sparkles, Copy, Check, ChevronDown } from 'lucide-react';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  challenge?: string | null;
  isLive?: boolean;
  timestamp: Date;
}

const QUICK_QUESTIONS = [
  { id: 'c1', challenge: 'C1', question: 'Why is this a zero-day threat and not a signature match?', color: 'challenge-badge-c1', desc: 'BiLSTM deviation detection' },
  { id: 'c2', challenge: 'C2', question: 'Why didn\'t the system fire during last month-end batch?', color: 'challenge-badge-c2', desc: 'Calendar-aware context' },
  { id: 'c3', challenge: 'C3', question: 'How many alerts did you suppress before escalating this?', color: 'challenge-badge-c3', desc: '4-layer suppression' },
  { id: 'c4', challenge: 'C4', question: 'How did you detect this if TLS 1.3 hides the payload?', color: 'challenge-badge-c4', desc: '3-layer TLS detection' },
];

const SOCAssistantPage: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '0',
      role: 'assistant',
      content: '**Welcome to BankSentinel SOC AI.**\n\nI can explain any alert, cite specific NRB/SWIFT/PCI-DSS controls, and walk you through detection reasoning for all 4 challenges.\n\nTry one of the quick questions below, or ask your own.',
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(scrollToBottom, [messages]);

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
            isLive: data.is_live_llm,
            timestamp: new Date(),
          },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: (Date.now() + 1).toString(),
            role: 'assistant',
            content: 'Error: Could not reach the SOC Assistant API. Ensure the backend is running.',
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
          content: 'Connection error. Start the backend with `uvicorn api.main:app --port 8000`.',
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const copyMessage = (id: string, content: string) => {
    navigator.clipboard.writeText(content);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="h-full flex gap-4 p-4 animate-fade-up">
      {/* Main Chat */}
      <div className="flex-1 flex flex-col glass-panel">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-background-border">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center">
              <Sparkles size={14} className="text-white" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">BankSentinel SOC AI</h2>
              <p className="text-[10px] text-text-muted">Gemini 2.0 Flash • Nepal Banking Context</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="live-badge live-badge-active">
              <span className="status-dot-online" style={{ width: 5, height: 5 }} />
              ACTIVE
            </span>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4 min-h-0">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-fade-up`}
            >
              <div
                className={`${msg.role === 'user' ? 'chat-bubble-user max-w-[70%]' : 'chat-bubble-ai max-w-[80%]'} relative group`}
              >
                <div className="text-sm text-text-primary whitespace-pre-wrap leading-relaxed">
                  {msg.content}
                </div>
                <div className="flex items-center justify-between mt-2 pt-2 border-t border-background-border/30">
                  <div className="flex items-center gap-2">
                    {msg.challenge && (
                      <span className={`challenge-badge challenge-badge-${msg.challenge.toLowerCase()}`}>
                        {msg.challenge}
                      </span>
                    )}
                    {msg.isLive !== undefined && (
                      <span className="text-[9px] text-text-muted">
                        {msg.isLive ? '✦ Live LLM' : '⬡ Fallback'}
                      </span>
                    )}
                  </div>
                  {msg.role === 'assistant' && (
                    <button
                      onClick={() => copyMessage(msg.id, msg.content)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity text-text-muted hover:text-text-primary"
                    >
                      {copied === msg.id ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="flex justify-start">
              <div className="chat-bubble-ai">
                <div className="typing-indicator flex gap-1">
                  <span /><span /><span />
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="px-6 py-4 border-t border-background-border">
          <div className="flex gap-3">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage(input)}
              placeholder="Ask about any alert, detection, or compliance question..."
              className="input-dark flex-1"
              disabled={isLoading}
            />
            <button
              onClick={() => sendMessage(input)}
              disabled={isLoading || !input.trim()}
              className="btn-primary px-4 py-2 disabled:opacity-40 flex items-center gap-2"
            >
              <Send size={14} />
              <span className="text-xs">Send</span>
            </button>
          </div>
        </div>
      </div>

      {/* Quick Questions Sidebar */}
      <div className="w-72 space-y-4 flex-shrink-0">
        <div className="glass-panel p-4">
          <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
            Quick Challenge Questions
          </h3>
          <div className="space-y-2">
            {QUICK_QUESTIONS.map((q) => (
              <button
                key={q.id}
                onClick={() => sendMessage(q.question)}
                disabled={isLoading}
                className="w-full text-left p-3 rounded-lg bg-background-elevated hover:bg-background-border transition-all disabled:opacity-40 group"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className={`challenge-badge ${q.color}`}>{q.challenge}</span>
                  <span className="text-[10px] text-text-muted">{q.desc}</span>
                </div>
                <div className="text-xs text-text-primary group-hover:text-white transition-colors">
                  {q.question}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Info Panel */}
        <div className="glass-panel p-4">
          <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">About</h3>
          <div className="space-y-2 text-[11px] text-text-muted leading-relaxed">
            <p>The SOC AI assistant cites specific controls from:</p>
            <ul className="space-y-1 list-disc list-inside">
              <li>NRB Cybersecurity Guidelines (4.2, 4.5)</li>
              <li>SWIFT CSP (6.1, 6.2, 7.4)</li>
              <li>PCI-DSS v4.0 (10.3, 11.5)</li>
              <li>ISO/IEC 27035</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SOCAssistantPage;
