import React from 'react';
import { useTokens } from '../context/TokenContext';
import './Notification.css';

const Notification = () => {
  const { notification } = useTokens();

  if (!notification) return null;

  return (
    <div className={`notification ${notification.type} show`}>
      {notification.message}
    </div>
  );
};

export default Notification;

