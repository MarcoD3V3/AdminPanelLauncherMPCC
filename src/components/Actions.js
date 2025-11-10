import React, { useState } from 'react';
import { useTokens } from '../context/TokenContext';
import GenerateTokenModal from './GenerateTokenModal';
import './Actions.css';

const Actions = () => {
  const { loadTokens, clearUsedTokens, showNotification } = useTokens();
  const [showGenerateModal, setShowGenerateModal] = useState(false);

  const handleRefresh = () => {
    loadTokens();
    showNotification('Lista actualizada', 'info');
  };

  const handleClearUsed = async () => {
    if (window.confirm('¿Estás seguro de que quieres eliminar todos los tokens usados?')) {
      await clearUsedTokens();
    }
  };

  return (
    <>
      <div className="actions">
        <button 
          className="btn btn-primary" 
          onClick={() => setShowGenerateModal(true)}
        >
          ➕ Generar Nuevo Token
        </button>
        <button className="btn btn-secondary" onClick={handleRefresh}>
          🔄 Actualizar Lista
        </button>
        <button className="btn btn-danger" onClick={handleClearUsed}>
          🗑️ Limpiar Tokens Usados
        </button>
      </div>
      {showGenerateModal && (
        <GenerateTokenModal onClose={() => setShowGenerateModal(false)} />
      )}
    </>
  );
};

export default Actions;

