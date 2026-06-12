import { setupServer } from 'msw/node';
import { handlers } from '@services/mock/handlers';

export const server = setupServer(...handlers);
