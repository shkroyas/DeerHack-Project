const useMock = import.meta.env.VITE_USE_MOCK_API === 'true';

type AgentsService = typeof import('./mock/agents.service').agentsService;

let impl: { agentsService: AgentsService };
if (useMock) impl = await import('./mock/agents.service');
else impl = await import('./real/agents.service');

export const agentsService = impl.agentsService;
