import React from 'react';

const Dashboard = () => {
    return (
        <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
            <h1>Dashboard</h1>
            <div style={{ display: 'flex', gap: '20px', marginTop: '20px' }}>
                <div style={{ flex: 1, padding: '20px', border: '1px solid #ccc', borderRadius: '8px' }}>
                    <h2>Statistics</h2>
                    <p>Overview of key metrics.</p>
                </div>
                <div style={{ flex: 1, padding: '20px', border: '1px solid #ccc', borderRadius: '8px' }}>
                    <h2>Recent Activity</h2>
                    <p>Latest updates and logs.</p>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;