import React, { useState } from 'react';
import { useTokens } from '../context/TokenContext';
import './GenerateTokenModal.css';

const GenerateTokenModal = ({ onClose }) => {
  const { generateTokens } = useTokens();
  const [count, setCount] = useState(1);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (count < 1 || count > 100) {
      alert('La cantidad debe estar entre 1 y 100');
      return;
    }

    setLoading(true);
    try {
      await generateTokens(count);
      onClose();
    } catch (error) {
      // El error ya se maneja en el contexto
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Generar Nuevo Token</h2>
          <button className="close-btn" onClick={onClose}>&times;</button>
        </div>
        <form className="modal-body" onSubmit={handleSubmit}>
          <label htmlFor="token-count">Cantidad de tokens a generar:</label>
          <input
            id="token-count"
            type="number"
            min="1"
            max="100"
            value={count}
            onChange={(e) => setCount(parseInt(e.target.value) || 1)}
            disabled={loading}
            required
          />
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
              Cancelar
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Generando...' : 'Generar'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default GenerateTokenModal;

