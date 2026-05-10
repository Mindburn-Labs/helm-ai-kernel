import React, { useEffect, useRef } from 'react';
import * as PIXI from 'pixi.js';

export interface CanvasElementProps {
  width?: number;
  height?: number;
  backgroundColor?: string;
  className?: string;
}

/**
 * Enterprise-scale Canvas Element utilizing PixiJS (v8 compatible architecture).
 * Provides a high-performance hardware-accelerated rendering surface.
 */
export function CanvasElement({ 
  width = 800, 
  height = 600, 
  backgroundColor = '#0b0c10',
  className = ''
}: CanvasElementProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const appRef = useRef<PIXI.Application | null>(null);

  useEffect(() => {
    let isMounted = true;
    
    const initPixi = async () => {
      if (!canvasRef.current) return;
      
      const app = new PIXI.Application();
      await app.init({
        canvas: canvasRef.current,
        width,
        height,
        backgroundColor: backgroundColor,
        resolution: window.devicePixelRatio || 1,
        autoDensity: true,
        antialias: true
      });
      
      if (!isMounted) {
        app.destroy(true);
        return;
      }
      
      appRef.current = app;

      // Draw a grid to demonstrate enterprise-grade layout rendering
      const grid = new PIXI.Graphics();
      grid.setStrokeStyle({ width: 1, color: 0x333333, alpha: 0.5 });
      
      const gridSize = 40;
      for (let x = 0; x <= width; x += gridSize) {
        grid.moveTo(x, 0);
        grid.lineTo(x, height);
      }
      for (let y = 0; y <= height; y += gridSize) {
        grid.moveTo(0, y);
        grid.lineTo(width, y);
      }
      grid.stroke();
      app.stage.addChild(grid);
      
      // Draw a canonical node
      const node = new PIXI.Graphics();
      node.roundRect(100, 100, 150, 80, 8);
      node.fill({ color: 0x1f2833 });
      node.setStrokeStyle({ width: 2, color: 0x66fcf1 });
      node.stroke();
      
      const text = new PIXI.Text({
        text: 'Canvas Node',
        style: {
          fontFamily: 'monospace',
          fontSize: 14,
          fill: 0xc5c6c7,
          align: 'center'
        }
      });
      text.x = 100 + (150 - text.width) / 2;
      text.y = 100 + (80 - text.height) / 2;
      
      app.stage.addChild(node);
      app.stage.addChild(text);
    };

    initPixi();

    return () => {
      isMounted = false;
      if (appRef.current) {
        appRef.current.destroy(true, { children: true, texture: true });
        appRef.current = null;
      }
    };
  }, [width, height, backgroundColor]);

  return (
    <div className={`helm-canvas-wrapper ${className}`} style={{ width, height, overflow: 'hidden', borderRadius: '8px' }}>
      <canvas ref={canvasRef} style={{ display: 'block', width: '100%', height: '100%' }} />
    </div>
  );
}
