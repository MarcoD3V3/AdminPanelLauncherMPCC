import React, { useState } from 'react';
import { useTokens } from '../context/TokenContext';
import './TokenTable.css';

const TokenTable = () => {
  const { tokens, loading, deleteToken, copyToken } = useTokens();
  const [searchTerm, setSearchTerm] = useState('');

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString('es-ES');
  };

  const filteredTokens = tokens.filter(token =>
    token.token.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Cargando tokens...</p>
      </div>
    );
  }

  return (
    <div className="token-table-container">
      <div className="search-bar">
        <input
          type="text"
          placeholder="Buscar token..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      <div className="table-wrapper">
        <table className="tokens-table">
          <thead>
            <tr>
              <th>Token</th>
              <th>Estado</th>
              <th>Fecha de Creación</th>
              <th>Fecha de Uso</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {filteredTokens.length === 0 ? (
              <tr>
                <td colSpan="5" className="no-tokens">
                  {searchTerm ? 'No se encontraron tokens' : 'No hay tokens disponibles'}
                </td>
              </tr>
            ) : (
              filteredTokens.map((token, index) => (
                <tr key={index}>
                  <td>
                    <div className="token-code">{token.token}</div>
                  </td>
                  <td>
                    <span className={`status-badge ${token.used ? 'status-used' : 'status-available'}`}>
                      {token.used ? 'Usado' : 'Disponible'}
                    </span>
                  </td>
                  <td>{formatDate(token.createdAt)}</td>
                  <td>{token.usedAt ? formatDate(token.usedAt) : '-'}</td>
                  <td>
                    <button
                      className="action-btn btn-danger"
                      onClick={() => {
                        if (window.confirm('¿Estás seguro de que quieres eliminar este token?')) {
                          deleteToken(token.token);
                        }
                      }}
                      title="Eliminar"
                    >
                      🗑️
                    </button>
                    <button
                      className="action-btn btn-success"
                      onClick={() => copyToken(token.token)}
                      title="Copiar"
                    >
                      📋
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default TokenTable;

