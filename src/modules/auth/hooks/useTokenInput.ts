import { useRef, KeyboardEvent, ClipboardEvent } from 'react';

export const useTokenInput = (length: number = 9) => {
    const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

    const handleInput = (index: number, e: React.ChangeEvent<HTMLInputElement>) => {
        const val = e.target.value;
        if (val.length === 1 && index < length - 1) {
            inputRefs.current[index + 1]?.focus();
        }
    };

    const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Backspace' && !e.currentTarget.value && index > 0) {
            inputRefs.current[index - 1]?.focus();
        }
    };

    const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
        e.preventDefault();
        const data = e.clipboardData.getData('text').trim();
        const numericData = data.replace(/\D/g, ''); // Garantir apenas números

        if (numericData.length > 0) {
            const digits = numericData.split('');
            for (let i = 0; i < length && i < digits.length; i++) {
                if (inputRefs.current[i]) {
                    inputRefs.current[i]!.value = digits[i];
                    // Trigger custom logic to update parent state if needed via ref form
                }
            }
            const focusIndex = Math.min(digits.length, length - 1);
            inputRefs.current[focusIndex]?.focus();
        }
    };

    return {
        inputRefs,
        handleInput,
        handleKeyDown,
        handlePaste,
        length
    };
};
