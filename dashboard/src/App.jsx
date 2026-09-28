import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import ScanList from './components/ScanList';
import ScanConfig from './components/ScanConfig';
import ScanDetail from './components/ScanDetail';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<ScanList />} />
        <Route path="/new" element={<ScanConfig />} />
        <Route path="/scans/:scanId" element={<ScanDetail />} />
      </Routes>
    </Layout>
  );
}

export default App;
