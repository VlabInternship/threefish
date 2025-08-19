// src/App.js
/* eslint-disable no-undef */
/* global BigInt */
import React, { useState } from 'react';
import './App.css';

// Threefish Cipher Implementation
const MASK64 = (1n << 64n) - 1n;

// Rotate left for 64-bit BigInt
function rotateLeft(x, n) {
  n = BigInt(n);
  return ((x << n) | (x >> (64n - n))) & MASK64;
}

// Threefish mix function
function mix(a, b, r) {
  a = a & MASK64;
  b = b & MASK64;
  const y0 = (a + b) & MASK64;
  const y1 = rotateLeft(b, r) ^ y0;
  return [y0, y1];
}

// Inverse mix function
function invertMix(y0, y1, r) {
  const b_rot = y1 ^ y0;
  const b = rotateLeft(b_rot, 64 - r);
  const a = (y0 - b) & MASK64;
  return [a, b];
}

// Rotation constants for Threefish-256
const rotationConstants = [
  [14, 16],
  [52, 57],
  [23, 40],
  [5, 37],
  [25, 33],
  [46, 12],
  [58, 22],
  [32, 32]
];

function getRotationConstant(round, pairIndex) {
  return rotationConstants[round % 8][pairIndex];
}

// Key schedule
function getSubkeys(key, tweak) {
  const k4 = key.reduce((acc, val) => acc ^ val, 0x1BD11BDAA9FC1A22n);
  const k = [...key, k4];
  const t2 = tweak[0] ^ tweak[1];
  const t = [...tweak, t2];
  
  const subkeys = [];
  for (let s = 0; s <= 18; s++) {
    subkeys.push([
      k[(s) % 5],
      (k[(s + 1) % 5] + t[s % 3]) & MASK64,
      (k[(s + 2) % 5] + t[(s + 1) % 3]) & MASK64,
      (k[(s + 3) % 5] + BigInt(s)) & MASK64
    ]);
  }
  return subkeys;
}

// Encryption function with step recording
function encryptBlock(key, tweak, plaintext) {
  const subkeys = getSubkeys(key, tweak);
  let state = [...plaintext];
  const steps = [];

  for (let d = 0; d < 72; d++) {
    if (d % 4 === 0) {
      const s = Math.floor(d / 4);
      state = state.map((word, i) => (word + subkeys[s][i]) & MASK64);
      steps.push({
        round: d,
        step: 'subkey',
        subkey: s,
        state: [...state],
        description: `Added subkey ${s}`
      });
    }

    // Mix pair 0
    const r0 = getRotationConstant(d, 0);
    [state[0], state[1]] = mix(state[0], state[1], r0);
    steps.push({
      round: d,
      step: 'mix',
      pair: 0,
      rotation: r0,
      state: [...state],
      description: `Mixed pair 0 with rotation ${r0}`
    });

    // Mix pair 1
    const r1 = getRotationConstant(d, 1);
    [state[2], state[3]] = mix(state[2], state[3], r1);
    steps.push({
      round: d,
      step: 'mix',
      pair: 1,
      rotation: r1,
      state: [...state],
      description: `Mixed pair 1 with rotation ${r1}`
    });

    // Permutation
    state = [state[0], state[3], state[2], state[1]];
    steps.push({
      round: d,
      step: 'permute',
      state: [...state],
      description: `Permuted words: [0,3,2,1]`
    });
  }

  // Final subkey
  state = state.map((word, i) => (word + subkeys[18][i]) & MASK64);
  steps.push({
    round: 72,
    step: 'subkey',
    subkey: 18,
    state: [...state],
    description: `Added final subkey 18`
  });

  return {
    ciphertext: state,
    steps: steps
  };
}

// Decryption function
function decryptBlock(key, tweak, ciphertext) {
  const subkeys = getSubkeys(key, tweak);
  let state = [...ciphertext];
  const steps = [];

  // Subtract final subkey
  state = state.map((word, i) => (word - subkeys[18][i]) & MASK64);
  steps.push({
    round: 72,
    step: 'subkey',
    subkey: 18,
    state: [...state],
    description: `Subtracted final subkey 18`
  });

  for (let d = 71; d >= 0; d--) {
    // Inverse permutation
    state = [state[0], state[3], state[2], state[1]];
    steps.push({
      round: d,
      step: 'permute',
      state: [...state],
      description: `Inverse permutation: [0,3,2,1]`
    });

    // Inverse mix pair 1
    const r1 = getRotationConstant(d, 1);
    [state[2], state[3]] = invertMix(state[2], state[3], r1);
    steps.push({
      round: d,
      step: 'mix',
      pair: 1,
      rotation: r1,
      state: [...state],
      description: `Inverse mixed pair 1 with rotation ${r1}`
    });

    // Inverse mix pair 0
    const r0 = getRotationConstant(d, 0);
    [state[0], state[1]] = invertMix(state[0], state[1], r0);
    steps.push({
      round: d,
      step: 'mix',
      pair: 0,
      rotation: r0,
      state: [...state],
      description: `Inverse mixed pair 0 with rotation ${r0}`
    });

    if (d % 4 === 0) {
      const s = Math.floor(d / 4);
      state = state.map((word, i) => (word - subkeys[s][i]) & MASK64);
      steps.push({
        round: d,
        step: 'subkey',
        subkey: s,
        state: [...state],
        description: `Subtracted subkey ${s}`
      });
    }
  }

  return {
    plaintext: state,
    steps: steps.reverse()
  };
}

// Helper functions
function hexToBigIntArray(hex, numWords) {
  const array = [];
  for (let i = 0; i < numWords; i++) {
    const wordHex = hex.substring(i * 16, (i + 1) * 16);
    array.push(BigInt('0x' + wordHex));
  }
  return array;
}

function bigIntArrayToHex(arr) {
  return arr.map(word => {
    const hex = word.toString(16);
    return hex.padStart(16, '0');
  }).join('');
}

function formatState(state) {
  return state.map(word => {
    const hex = word.toString(16).padStart(16, '0');
    return hex.match(/.{1,4}/g).join(' ');
  }).join(' | ');
}

function App() {
  // State management
  const [activeTab, setActiveTab] = useState('theory');
  const [key, setKey] = useState('0000000000000000000000000000000000000000000000000000000000000000');
  const [tweak, setTweak] = useState('00000000000000000000000000000000');
  const [input, setInput] = useState('0000000000000000000000000000000000000000000000000000000000000000');
  const [output, setOutput] = useState('');
  const [steps, setSteps] = useState([]);
  const [currentStep, setCurrentStep] = useState(0);
  const [operation, setOperation] = useState('encrypt');
  
  // Handle encryption/decryption
  const handleProcess = () => {
    if (key.length !== 64 || !/^[0-9a-fA-F]+$/.test(key)) {
      alert('Key must be 64 hex digits');
      return;
    }
    if (tweak.length !== 32 || !/^[0-9a-fA-F]+$/.test(tweak)) {
      alert('Tweak must be 32 hex digits');
      return;
    }
    if (input.length !== 64 || !/^[0-9a-fA-F]+$/.test(input)) {
      alert('Input must be 64 hex digits');
      return;
    }
    
    const keyArray = hexToBigIntArray(key, 4);
    const tweakArray = hexToBigIntArray(tweak, 2);
    const inputArray = hexToBigIntArray(input, 4);
    
    let result;
    if (operation === 'encrypt') {
      result = encryptBlock(keyArray, tweakArray, inputArray);
      setOutput(bigIntArrayToHex(result.ciphertext));
    } else {
      result = decryptBlock(keyArray, tweakArray, inputArray);
      setOutput(bigIntArrayToHex(result.plaintext));
    }
    
    setSteps(result.steps);
    setCurrentStep(0);
  };
  
  // Navigation through steps
  const nextStep = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };
  
  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };
  
  // Format a step for display
  const renderStep = (step, index) => {
    return (
      <div key={index} className={`step ${index === currentStep ? 'active' : ''}`}>
        <div className="step-header">
          <span className="round">Round {step.round}</span>
          <span className="step-type">{step.step}</span>
        </div>
        <div className="step-description">{step.description}</div>
        <div className="state">
          {formatState(step.state).split(' | ').map((word, i) => (
            <div key={i} className="word">{word}</div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="app">
      <header className="header">
        <h1>Threefish Cipher Explorer</h1>
        <p>A 256-bit block cipher with visual step-by-step demonstration</p>
      </header>
      
      <nav className="tabs">
        <button 
          className={activeTab === 'theory' ? 'active' : ''} 
          onClick={() => setActiveTab('theory')}
        >
          Theory
        </button>
        <button 
          className={activeTab === 'example' ? 'active' : ''} 
          onClick={() => setActiveTab('example')}
        >
          Example
        </button>
        <button 
          className={activeTab === 'demo' ? 'active' : ''} 
          onClick={() => setActiveTab('demo')}
        >
          Demonstration
        </button>
      </nav>
      
      <main className="content">
        {activeTab === 'theory' && (
          <div className="theory">
            <h2>Threefish Cipher Overview</h2>
            <p>
              Threefish is a symmetric-key tweakable block cipher designed as part of the Skein hash function, 
              a finalist in the NIST SHA-3 competition. It's known for its simplicity, security, and performance.
            </p>
            
            <h3>Key Features</h3>
            <ul>
              <li><strong>Block Size:</strong> 256, 512, or 1024 bits</li>
              <li><strong>Key Size:</strong> Matches block size</li>
              <li><strong>Tweak:</strong> 128-bit additional parameter</li>
              <li><strong>Rounds:</strong> 72 for 256-bit version</li>
              <li><strong>Operations:</strong> Addition, rotation, and XOR</li>
            </ul>
            
            <h3>Algorithm Structure</h3>
            <p>
              Threefish operates on 64-bit words and consists of:
            </p>
            <ol>
              <li><strong>Key Schedule:</strong> Expands key and tweak into round keys</li>
              <li><strong>Round Function:</strong> 
                <ul>
                  <li><strong>Subkey Addition:</strong> Every 4 rounds</li>
                  <li><strong>MIX Function:</strong> Combines two words with rotation</li>
                  <li><strong>Permutation:</strong> Rearranges words between rounds</li>
                </ul>
              </li>
            </ol>
            
            <div className="mix-visual">
              <div className="mix-formula">
                <p>MIX Function:</p>
                <p>y0 = x0 + x1</p>
                <p>y1 = (x1 ≪ R) ⊕ y0</p>
              </div>
              <div className="mix-diagram">
                <div className="mix-box">
                  <div>Input: (x0, x1)</div>
                  <div className="arrow">↓</div>
                  <div>Addition: x0 + x1</div>
                  <div className="arrow">↓</div>
                  <div>Rotation: x1 ≪ R</div>
                  <div className="arrow">↓</div>
                  <div>XOR: (x1 ≪ R) ⊕ (x0 + x1)</div>
                  <div className="arrow">↓</div>
                  <div>Output: (y0, y1)</div>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {activeTab === 'example' && (
          <div className="example">
            <h2>Threefish-256 Example</h2>
            <p>
              This example demonstrates the encryption of an all-zero block with an all-zero key and tweak.
            </p>
            
            <div className="example-values">
              <div>
                <h3>Input Values</h3>
                <p><strong>Key:</strong> 0000000000000000000000000000000000000000000000000000000000000000</p>
                <p><strong>Tweak:</strong> 00000000000000000000000000000000</p>
                <p><strong>Plaintext:</strong> 0000000000000000000000000000000000000000000000000000000000000000</p>
              </div>
              
              <div>
                <h3>Output</h3>
                <p><strong>Ciphertext:</strong> 94eea8b1f2ada84a ddfdd88f17c2884a 5e8cbb2c7b8f9f5f 00b5bafc9d1b3f0a</p>
              </div>
            </div>
            
            <div className="round-example">
              <h3>Round 0 Operations</h3>
              <div className="round-step">
                <h4>Subkey Addition</h4>
                <p>Add subkey 0: [0, 0, 0, 0]</p>
                <p>State remains: [0, 0, 0, 0]</p>
              </div>
              
              <div className="round-step">
                <h4>MIX Pair 0</h4>
                <p>Rotation: 14</p>
                <p>y0 = 0 + 0 = 0</p>
                <p>y1 = rotate(0, 14) ⊕ 0 = 0</p>
              </div>
              
              <div className="round-step">
                <h4>MIX Pair 1</h4>
                <p>Rotation: 16</p>
                <p>y0 = 0 + 0 = 0</p>
                <p>y1 = rotate(0, 16) ⊕ 0 = 0</p>
              </div>
              
              <div className="round-step">
                <h4>Permutation</h4>
                <p>Word order: [0, 3, 2, 1] → [0, 0, 0, 0]</p>
              </div>
            </div>
          </div>
        )}
        
        {activeTab === 'demo' && (
          <div className="demo">
            <div className="controls">
              <div className="input-group">
                <label>Operation:</label>
                <select value={operation} onChange={(e) => setOperation(e.target.value)}>
                  <option value="encrypt">Encrypt</option>
                  <option value="decrypt">Decrypt</option>
                </select>
              </div>
              
              <div className="input-group">
                <label>Key (64 hex digits):</label>
                <input 
                  type="text" 
                  value={key} 
                  onChange={(e) => setKey(e.target.value)} 
                />
              </div>
              
              <div className="input-group">
                <label>Tweak (32 hex digits):</label>
                <input 
                  type="text" 
                  value={tweak} 
                  onChange={(e) => setTweak(e.target.value)} 
                />
              </div>
              
              <div className="input-group">
                <label>Input (64 hex digits):</label>
                <input 
                  type="text" 
                  value={input} 
                  onChange={(e) => setInput(e.target.value)} 
                />
              </div>
              
              <button className="process-btn" onClick={handleProcess}>
                {operation === 'encrypt' ? 'Encrypt' : 'Decrypt'}
              </button>
              
              <div className="input-group output">
                <label>Output:</label>
                <div className="output-value">{output}</div>
              </div>
            </div>
            
            {steps.length > 0 && (
              <div className="visualization">
                <h3>Step-by-Step Visualization</h3>
                
                <div className="step-navigation">
                  <button onClick={prevStep} disabled={currentStep === 0}>
                    Previous Step
                  </button>
                  <span>Step {currentStep + 1} of {steps.length}</span>
                  <button onClick={nextStep} disabled={currentStep === steps.length - 1}>
                    Next Step
                  </button>
                </div>
                
                <div className="current-step-info">
                  <h4>{steps[currentStep].description}</h4>
                  <div className="state">
                    {formatState(steps[currentStep].state).split(' | ').map((word, i) => (
                      <div key={i} className="word">{word}</div>
                    ))}
                  </div>
                </div>
                
                <div className="step-progress">
                  {steps.map((step, index) => (
                    <div 
                      key={index} 
                      className={`step-indicator ${index === currentStep ? 'active' : ''}`}
                      onClick={() => setCurrentStep(index)}
                    >
                      <div className="round-num">R{step.round}</div>
                      <div className="step-type">{step.step.charAt(0)}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
      
     
    </div>
  );
}

export default App;