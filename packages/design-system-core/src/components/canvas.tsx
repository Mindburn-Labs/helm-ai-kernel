import React, { useEffect, useRef } from 'react';
import * as PIXI from 'pixi.js';

export interface CanvasNode {
  readonly id: string;
  readonly label: string;
  readonly group: string;
  readonly verdict: "ALLOW" | "DENY" | "ESCALATE";
  readonly proofStatus: string;
  readonly summary: string;
}

export interface CanvasEdge {
  readonly from: string;
  readonly to: string;
}

export interface CanvasElementProps {
  readonly width?: number;
  readonly height?: number;
  readonly backgroundColor?: string;
  readonly className?: string;
  readonly nodes?: readonly CanvasNode[];
  readonly edges?: readonly CanvasEdge[];
  readonly onSelectNode?: (id: string) => void;
  readonly selectedNodeId?: string;
}

/**
 * Enterprise-scale Canvas Element utilizing PixiJS (v8 compatible architecture).
 * Renders an interactive, zoomable, draggable DAG Trace Visualizer for HELM runs.
 */
export function CanvasElement({ 
  width = 800, 
  height = 400, 
  backgroundColor,
  className = '',
  nodes = [],
  edges = [],
  onSelectNode,
  selectedNodeId
}: CanvasElementProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const appRef = useRef<PIXI.Application | null>(null);

  useEffect(() => {
    let isMounted = true;
    let animFrameId: number;
    let dashOffset = 0;
    
    const initPixi = async () => {
      if (!canvasRef.current) return;
      
      const app = new PIXI.Application();
      const resolvedBackgroundColor =
        backgroundColor ??
        (getComputedStyle(document.documentElement)
          .getPropertyValue('--helm-bg-inset')
          .trim() || '#07090c');
      
      await app.init({
        canvas: canvasRef.current,
        width,
        height,
        backgroundColor: resolvedBackgroundColor,
        resolution: window.devicePixelRatio || 1,
        autoDensity: true,
        antialias: true
      });
      
      if (!isMounted) {
        app.destroy(true);
        return;
      }
      
      appRef.current = app;

      // Create a zoomable, pannable camera viewport container
      const viewport = new PIXI.Container();
      app.stage.addChild(viewport);

      // Make the app stage interactive for dragging/panning
      app.stage.eventMode = 'static';
      app.stage.hitArea = new PIXI.Rectangle(0, 0, width, height);

      let isDragging = false;
      let dragStart = { x: 0, y: 0 };
      let cameraStart = { x: 0, y: 0 };

      app.stage.on('pointerdown', (e) => {
        isDragging = true;
        dragStart.x = e.global.x;
        dragStart.y = e.global.y;
        cameraStart.x = viewport.x;
        cameraStart.y = viewport.y;
      });

      app.stage.on('pointermove', (e) => {
        if (!isDragging) return;
        const dx = e.global.x - dragStart.x;
        const dy = e.global.y - dragStart.y;
        viewport.x = cameraStart.x + dx;
        viewport.y = cameraStart.y + dy;
      });

      const onPointerUp = () => {
        isDragging = false;
      };
      app.stage.on('pointerup', onPointerUp);
      app.stage.on('pointerupoutside', onPointerUp);

      // Zoom support via mouse wheel
      const handleWheel = (e: WheelEvent) => {
        e.preventDefault();
        const zoomFactor = 1.05;
        const localPos = viewport.toLocal(new PIXI.Point(e.offsetX, e.offsetY));
        const oldScale = viewport.scale.x;
        let newScale = oldScale;

        if (e.deltaY < 0) {
          newScale = Math.min(newScale * zoomFactor, 3);
        } else {
          newScale = Math.max(newScale / zoomFactor, 0.4);
        }

        viewport.scale.set(newScale);
        viewport.x = e.offsetX - localPos.x * newScale;
        viewport.y = e.offsetY - localPos.y * newScale;
      };

      canvasRef.current.addEventListener('wheel', handleWheel, { passive: false });

      // Draw standard grid
      const grid = new PIXI.Graphics();
      grid.setStrokeStyle({ width: 1, color: 0x1f2630, alpha: 0.4 });
      const maxGridSize = 2500;
      const stepSize = 50;
      for (let x = -maxGridSize; x <= maxGridSize; x += stepSize) {
        grid.moveTo(x, -maxGridSize);
        grid.lineTo(x, maxGridSize);
      }
      for (let y = -maxGridSize; y <= maxGridSize; y += stepSize) {
        grid.moveTo(-maxGridSize, y);
        grid.lineTo(maxGridSize, y);
      }
      grid.stroke();
      viewport.addChild(grid);

      // Map dynamic positions to nodes
      const nodeMap = new Map<string, { x: number; y: number; width: number; height: number }>();
      const nodeWidth = 200;
      const nodeHeight = 76;
      const horizontalSpacing = 280;
      const verticalOffset = 100;

      // Arrange nodes in a beautiful sequential DAG tree
      nodes.forEach((node, index) => {
        const x = 50 + index * horizontalSpacing;
        // Alternate heights slightly for visual depth and to prevent overlaps
        const y = height / 2 - nodeHeight / 2 + (index % 2 === 0 ? -verticalOffset / 2 : verticalOffset / 2);
        nodeMap.set(node.id, { x, y, width: nodeWidth, height: nodeHeight });
      });

      // Graphics layer for connections
      const edgeGraphics = new PIXI.Graphics();
      viewport.addChild(edgeGraphics);

      // Animate flowing telemetry data on connection lines
      app.ticker.add((ticker) => {
        dashOffset = (dashOffset + ticker.deltaTime * 0.9) % 30;
        
        edgeGraphics.clear();
        
        // Draw connection edges
        edges.forEach((edge) => {
          const fromNode = nodeMap.get(edge.from);
          const toNode = nodeMap.get(edge.to);
          if (!fromNode || !toNode) return;

          const startX = fromNode.x + fromNode.width;
          const startY = fromNode.y + fromNode.height / 2;
          const endX = toNode.x;
          const endY = toNode.y + toNode.height / 2;

          // Compute smooth cubic bezier handles for fluid flow lines
          const cp1X = startX + (endX - startX) / 2;
          const cp1Y = startY;
          const cp2X = startX + (endX - startX) / 2;
          const cp2Y = endY;

          // Draw the base path curve
          edgeGraphics.setStrokeStyle({ width: 2, color: 0x1f2630, alpha: 0.8 });
          edgeGraphics.moveTo(startX, startY);
          edgeGraphics.bezierCurveTo(cp1X, cp1Y, cp2X, cp2Y, endX, endY);
          edgeGraphics.stroke();

          // Draw floating glowing neon dashes for active data flow
          edgeGraphics.setStrokeStyle({ width: 2.5, color: 0x66fcf1, alpha: 0.65 });
          
          // Draw dashed flows along the bezier curve
          let points: PIXI.Point[] = [];
          const steps = 30;
          for (let i = 0; i <= steps; i++) {
            const t = i / steps;
            const mt = 1 - t;
            // Bezier formula
            const px = mt * mt * mt * startX + 3 * mt * mt * t * cp1X + 3 * mt * t * t * cp2X + t * t * t * endX;
            const py = mt * mt * mt * startY + 3 * mt * mt * t * cp1Y + 3 * mt * t * t * cp2Y + t * t * t * endY;
            points.push(new PIXI.Point(px, py));
          }

          // Apply dash offset animation
          let drawing = true;
          let currentLen = -dashOffset;
          edgeGraphics.moveTo(points[0].x, points[0].y);
          for (let i = 1; i < points.length; i++) {
            const p1 = points[i - 1];
            const p2 = points[i];
            const segmentLen = Math.hypot(p2.x - p1.x, p2.y - p1.y);
            currentLen += segmentLen;
            
            if (currentLen > 0) {
              if (drawing) {
                edgeGraphics.lineTo(p2.x, p2.y);
              } else {
                edgeGraphics.moveTo(p2.x, p2.y);
              }
              // Alternating dash size
              currentLen = 0;
              drawing = !drawing;
            } else if (drawing) {
              edgeGraphics.lineTo(p2.x, p2.y);
            }
          }
          edgeGraphics.stroke();
        });
      });

      // Draw the nodes
      nodes.forEach((node) => {
        const layout = nodeMap.get(node.id);
        if (!layout) return;

        // Custom status color palette
        let statusColor = 0xa5afbd; // Slate Gray
        if (node.verdict === 'ALLOW') statusColor = 0x3fb984; // Emerald
        if (node.verdict === 'DENY') statusColor = 0xe5484d; // Crimson
        if (node.verdict === 'ESCALATE') statusColor = 0xf5a524; // Amber

        const isSelected = selectedNodeId === node.id;
        const strokeColor = isSelected ? 0x75b4ff : statusColor;
        const strokeWidth = isSelected ? 3.5 : 2;

        const nodeGroup = new PIXI.Container();
        nodeGroup.x = layout.x;
        nodeGroup.y = layout.y;
        nodeGroup.eventMode = 'static';
        nodeGroup.cursor = 'pointer';

        // Node click trigger
        nodeGroup.on('pointerdown', (e) => {
          e.stopPropagation();
          if (onSelectNode) onSelectNode(node.id);
        });

        // 1. Draw glowing dropshadow under node
        const shadow = new PIXI.Graphics();
        shadow.roundRect(-3, -3, layout.width + 6, layout.height + 6, 12);
        shadow.fill({ color: statusColor, alpha: isSelected ? 0.22 : 0.06 });
        nodeGroup.addChild(shadow);

        // 2. Draw glassy node background
        const bg = new PIXI.Graphics();
        bg.roundRect(0, 0, layout.width, layout.height, 10);
        bg.fill({ color: 0x0e1218, alpha: 0.9 });
        bg.setStrokeStyle({ width: strokeWidth, color: strokeColor, alpha: isSelected ? 0.95 : 0.7 });
        bg.stroke();
        nodeGroup.addChild(bg);

        // 3. Status indicator dot inside the node
        const dot = new PIXI.Graphics();
        dot.circle(18, 22, 5);
        dot.fill({ color: statusColor });
        nodeGroup.addChild(dot);

        // 4. Node Title text (monospaced high contrast)
        const titleText = new PIXI.Text({
          text: node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label,
          style: {
            fontFamily: 'monospace',
            fontSize: 13,
            fontWeight: 'bold',
            fill: isSelected ? 0x75b4ff : 0xe6ecf2,
          }
        });
        titleText.x = 32;
        titleText.y = 14;
        nodeGroup.addChild(titleText);

        // 5. Node Group details tag (e.g. connector, capability)
        const groupText = new PIXI.Text({
          text: node.group.toUpperCase(),
          style: {
            fontFamily: 'sans-serif',
            fontSize: 9,
            fontWeight: '900',
            fill: 0x8b97a7,
            letterSpacing: 1
          }
        });
        groupText.x = 32;
        groupText.y = 32;
        nodeGroup.addChild(groupText);

        // 6. Node Summary snippet
        const summaryText = new PIXI.Text({
          text: node.summary.length > 32 ? node.summary.slice(0, 29) + '...' : node.summary,
          style: {
            fontFamily: 'sans-serif',
            fontSize: 10,
            fill: 0xa8b3c2,
          }
        });
        summaryText.x = 18;
        summaryText.y = 48;
        nodeGroup.addChild(summaryText);

        viewport.addChild(nodeGroup);
      });

      // Center the camera on the node DAG flow
      if (nodes.length > 0) {
        const totalFlowWidth = nodes.length * horizontalSpacing;
        viewport.x = (width - totalFlowWidth + horizontalSpacing) / 2 - 80;
        viewport.y = height / 2 - nodeHeight / 2;
      }
    };

    initPixi();

    return () => {
      isMounted = false;
      if (appRef.current) {
        appRef.current.destroy(true, { children: true, texture: true });
        appRef.current = null;
      }
    };
  }, [width, height, backgroundColor, nodes, edges, selectedNodeId]);

  return (
    <div className={`helm-canvas-wrapper ${className}`} style={{ width, height, overflow: 'hidden', borderRadius: '12px', border: '1px solid var(--color-glass-border)', boxShadow: 'var(--shadow-hairline)' }}>
      <canvas ref={canvasRef} style={{ display: 'block', width: '100%', height: '100%' }} />
    </div>
  );
}
