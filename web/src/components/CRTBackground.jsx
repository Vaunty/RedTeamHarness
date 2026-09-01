import { useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { EffectComposer, Bloom, Noise, ChromaticAberration, Scanline } from '@react-three/postprocessing'
import { BlendFunction } from 'postprocessing'
import * as THREE from 'three'

function ParticleGrid() {
  const pointsRef = useRef()

  // Create a grid of points
  const particleCount = 2000
  const positions = new Float32Array(particleCount * 3)
  for (let i = 0; i < particleCount; i++) {
    positions[i * 3] = (Math.random() - 0.5) * 20
    positions[i * 3 + 1] = (Math.random() - 0.5) * 20
    positions[i * 3 + 2] = (Math.random() - 0.5) * 10 - 5
  }

  useFrame((state) => {
    if (pointsRef.current) {
      pointsRef.current.rotation.y = state.clock.elapsedTime * 0.05
      pointsRef.current.position.z = Math.sin(state.clock.elapsedTime * 0.2) * 2
    }
  })

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={particleCount}
          array={positions}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.05}
        color="#00ff88"
        transparent
        opacity={0.4}
        blending={THREE.AdditiveBlending}
      />
    </points>
  )
}

function WireframeTunnel() {
  const meshRef = useRef()

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.z = state.clock.elapsedTime * 0.1
      meshRef.current.position.z = (state.clock.elapsedTime * 2) % 4
    }
  })

  return (
    <mesh ref={meshRef} position={[0, 0, -10]}>
      <cylinderGeometry args={[8, 8, 20, 16, 20, true]} />
      <meshBasicMaterial
        color="#003311"
        wireframe
        transparent
        opacity={0.3}
      />
    </mesh>
  )
}

export default function CRTBackground() {
  return (
    <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', zIndex: -1, background: '#050806' }}>
      <Canvas camera={{ position: [0, 0, 5], fov: 60 }}>
        <fog attach="fog" args={['#050806', 5, 15]} />
        <ParticleGrid />
        <WireframeTunnel />
        
        <EffectComposer disableNormalPass>
          <Bloom 
            luminanceThreshold={0.2} 
            luminanceSmoothing={0.9} 
            intensity={1.5} 
            kernelSize={5}
            mipmapBlur
          />
          <Noise 
            premultiply 
            blendFunction={BlendFunction.ADD} 
            opacity={0.6} 
          />
          <Scanline 
            blendFunction={BlendFunction.OVERLAY} 
            density={2.5} 
            opacity={0.2} 
          />
          <ChromaticAberration 
            blendFunction={BlendFunction.NORMAL}
            offset={[0.002, 0.002]} 
            radialModulation={false}
            modulationOffset={0.0}
          />
        </EffectComposer>
      </Canvas>
    </div>
  )
}
