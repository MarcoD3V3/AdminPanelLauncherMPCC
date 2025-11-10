import React from 'react';
import './App.css';
import Header from './components/Header';
import Stats from './components/Stats';
import Actions from './components/Actions';
import TokenTable from './components/TokenTable';
import GenerateTokenModal from './components/GenerateTokenModal';
import Notification from './components/Notification';
import { TokenProvider } from './context/TokenContext';

function App() {
  return (
    <TokenProvider>
      <div className="app-container">
        <Header />
        <Stats />
        <Actions />
        <TokenTable />
        <GenerateTokenModal />
        <Notification />
      </div>
    </TokenProvider>
  );
}

export default App;

