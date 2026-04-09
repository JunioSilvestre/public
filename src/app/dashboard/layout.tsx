import { DashboardLayout } from '@/modules/dashboard/components/layout/DashboardLayout';

export default function Layout({ children }: { children: React.ReactNode }) {
    return (
        <DashboardLayout>
            {children}
        </DashboardLayout>
    );
}
