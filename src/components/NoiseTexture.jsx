// SVG noise texture overlay — adds subtle print/poster texture to entire app
// Fixed position, full viewport, 3% opacity, mix-blend-overlay
// Purely decorative — aria-hidden

export default function NoiseTexture() {
  return (
    <svg
      className="noise-overlay"
      aria-hidden="true"
      xmlns="http://www.w3.org/2000/svg"
    >
      <filter id="noise-filter">
        <feTurbulence
          type="fractalNoise"
          baseFrequency="0.8"
          numOctaves="4"
          stitchTiles="stitch"
        />
        <feColorMatrix type="saturate" values="0" />
      </filter>
      <rect width="100%" height="100%" filter="url(#noise-filter)" />
    </svg>
  )
}
