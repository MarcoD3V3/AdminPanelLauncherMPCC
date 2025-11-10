import React from 'react';
import { useTokens } from '../context/TokenContext';
import './Stats.css';

const Stats = () => {
  const { stats } = useTokens();

  return (
    <div className="stats">
      <div className="stat-card">
        <div className="stat-number">{stats.total}</div>
        <div className="stat-label">Total Tokens</div>
      </div>
      <div className="stat-card">
        <div className="stat-number">{stats.used}</div>
        <div className="stat-label">Tokens Usados</div>
      </div>
      <div className="stat-card">
        <div className="stat-number">{stats.available}</div>
        <div className="stat-label">Tokens Disponibles</div>
      </div>
    </div>
  );
};

export default Stats;

