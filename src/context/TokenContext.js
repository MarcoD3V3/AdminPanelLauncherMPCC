import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const TokenContext = createContext();

// Detectar automáticamente la URL del servidor
const API_URL = window.location.origin + '/api';

export const useTokens = () => {
  const context = useContext(TokenContext);
  if (!context) {
    throw new Error('useTokens must be used within a TokenProvider');
  }
  return context;
};

export const TokenProvider = ({ children }) => {
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState(null);

  // Cargar tokens desde el servidor
  const loadTokens = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_URL}/tokens`);
      if (!response.ok) throw new Error('Error al cargar tokens');
      
      const data = await response.json();
      setTokens(data);
    } catch (error) {
      console.error('Error:', error);
      showNotification('Error al cargar tokens: ' + error.message, 'error');
      // Cargar desde localStorage como fallback
      const savedTokens = localStorage.getItem('tokens');
      if (savedTokens) {
        setTokens(JSON.parse(savedTokens));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  // Generar nuevos tokens
  const generateTokens = async (count) => {
    try {
      const response = await fetch(`${API_URL}/tokens/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ count })
      });
      
      if (!response.ok) throw new Error('Error al generar tokens');
      
      const result = await response.json();
      showNotification(`${result.tokens.length} token(s) generado(s) exitosamente`, 'success');
      await loadTokens();
      return result;
    } catch (error) {
      console.error('Error:', error);
      showNotification('Error al generar tokens: ' + error.message, 'error');
      throw error;
    }
  };

  // Eliminar un token
  const deleteToken = async (token) => {
    try {
      const response = await fetch(`${API_URL}/tokens/${encodeURIComponent(token)}`, {
        method: 'DELETE'
      });
      
      if (!response.ok) throw new Error('Error al eliminar token');
      
      showNotification('Token eliminado exitosamente', 'success');
      await loadTokens();
    } catch (error) {
      console.error('Error:', error);
      showNotification('Error al eliminar token: ' + error.message, 'error');
    }
  };

  // Limpiar tokens usados
  const clearUsedTokens = async () => {
    try {
      const response = await fetch(`${API_URL}/tokens/clear-used`, {
        method: 'DELETE'
      });
      
      if (!response.ok) throw new Error('Error al limpiar tokens');
      
      showNotification('Tokens usados eliminados exitosamente', 'success');
      await loadTokens();
    } catch (error) {
      console.error('Error:', error);
      showNotification('Error al limpiar tokens: ' + error.message, 'error');
    }
  };

  // Copiar token al portapapeles
  const copyToken = async (token) => {
    try {
      await navigator.clipboard.writeText(token);
      showNotification('Token copiado al portapapeles', 'success');
    } catch (error) {
      // Fallback para navegadores antiguos
      const textArea = document.createElement('textarea');
      textArea.value = token;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      showNotification('Token copiado al portapapeles', 'success');
    }
  };

  // Mostrar notificación
  const showNotification = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => {
      setNotification(null);
    }, 3000);
  };

  // Calcular estadísticas
  const stats = {
    total: tokens.length,
    used: tokens.filter(t => t.used).length,
    available: tokens.filter(t => !t.used).length
  };

  // Cargar tokens al montar
  useEffect(() => {
    loadTokens();
  }, [loadTokens]);

  const value = {
    tokens,
    loading,
    stats,
    loadTokens,
    generateTokens,
    deleteToken,
    clearUsedTokens,
    copyToken,
    showNotification,
    notification
  };

  return (
    <TokenContext.Provider value={value}>
      {children}
    </TokenContext.Provider>
  );
};

