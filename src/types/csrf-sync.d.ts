// Basic type declaration for csrf-sync as @types/csrf-sync is unavailable
declare module 'csrf-sync' {
    import { Request, Response, NextFunction } from 'express';

    interface CsrfSyncOptions {
        getTokenFromState?: (req: Request) => string | undefined | null;
        getTokenFromRequest: (req: Request) => string | undefined | null;
        storeTokenInState?: (req: Request, token: string) => void;
        size?: number;
        secret?: string; // Although library might generate one if not provided
        ignoredMethods?: string[];
        saltLength?: number;
        secretLength?: number;
        invalidCsrfTokenError?: Error;
        token?: string; // Deprecated? Check library docs
    }

    interface CsrfSyncProtection {
        csrfSynchronisedProtection: (req: Request, res: Response, next: NextFunction) => void;
        generateToken: (req: Request) => string;
        invalidCsrfTokenError: Error; // Allow customization
    }

    export function csrfSync(options: CsrfSyncOptions): CsrfSyncProtection;
}
