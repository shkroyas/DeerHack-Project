import { twMerge } from 'tailwind-merge';
import clsx from 'clsx';

export const cn = (...inputs: Array<string | false | null | undefined>) => twMerge(clsx(inputs));
