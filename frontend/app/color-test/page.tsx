// app/color-test/page.tsx
"use client";

import React from "react";

export default function ColorTest() {
  return (
    <div className="min-h-screen p-8 bg-background text-foreground">
      <div className="max-w-5xl mx-auto">
        <h1 className="text-4xl font-bold mb-2">Theme Color Preview</h1>
        <p className="text-muted-foreground mb-10">
          Light Mode vs Dark Mode using your new palette
        </p>

        {/* Toggle Button */}
        <button
          onClick={() => document.documentElement.classList.toggle("dark")}
          className="mb-12 px-6 py-3 bg-primary text-primary-foreground rounded-xl font-medium hover:bg-primary/90 transition-colors"
        >
          Toggle Dark Mode
        </button>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
          {/* Light Mode */}
          <div>
            <h2 className="text-2xl font-semibold mb-6 text-foreground">
              Light Mode
            </h2>

            <div className="space-y-6">
              <ColorSwatch
                name="Background"
                color="bg-background"
                hex="#F3E3D0"
              />
              <ColorSwatch
                name="Card / Popover"
                color="bg-card"
                hex="#F3E3D0"
              />
              <ColorSwatch
                name="Primary"
                color="bg-primary"
                hex="#81A6C6"
                text="text-primary-foreground"
              />
              <ColorSwatch
                name="Secondary"
                color="bg-secondary"
                hex="#AACDDC"
              />
              <ColorSwatch name="Muted" color="bg-muted" hex="#D2C4B4" />
              <ColorSwatch
                name="Border"
                color="border border-border"
                hex="#D2C4B4"
                isBorder
              />
              <ColorSwatch
                name="Foreground"
                color="bg-foreground"
                hex="#222"
                text="text-background"
              />
            </div>
          </div>

          {/* Dark Mode */}
          <div className="dark">
            <h2 className="text-2xl font-semibold mb-6 text-foreground">
              Dark Mode
            </h2>

            <div className="space-y-6">
              <ColorSwatch
                name="Background"
                color="bg-background"
                hex="#0B1F38"
              />
              <ColorSwatch
                name="Card / Popover"
                color="bg-card"
                hex="#1C2F4A"
              />
              <ColorSwatch
                name="Primary"
                color="bg-primary"
                hex="#81A6C6"
                text="text-primary-foreground"
              />
              <ColorSwatch
                name="Secondary"
                color="bg-secondary"
                hex="#AACDDC"
              />
              <ColorSwatch name="Muted" color="bg-muted" hex="#2A3A55" />
              <ColorSwatch
                name="Border"
                color="border border-border"
                hex="#FFFFFF22"
                isBorder
              />
              <ColorSwatch
                name="Foreground"
                color="bg-foreground"
                hex="#F3E3D0"
                text="text-background"
              />
            </div>
          </div>
        </div>

        <div className="mt-16 text-center text-sm text-muted-foreground">
          Click the button above to switch between Light and Dark mode
        </div>
      </div>
    </div>
  );
}

function ColorSwatch({
  name,
  color,
  hex,
  text = "text-foreground",
  isBorder = false,
}: {
  name: string;
  color: string;
  hex: string;
  text?: string;
  isBorder?: boolean;
}) {
  return (
    <div className="flex items-center gap-4">
      <div
        className={`w-20 h-20 rounded-2xl flex-shrink-0 border border-border ${color} ${isBorder ? "border-4" : ""}`}
      />
      <div>
        <p className="font-medium">{name}</p>
        <p className="text-sm text-muted-foreground font-mono">{hex}</p>
        <p className={`text-xs mt-1 ${text}`}>Sample text</p>
      </div>
    </div>
  );
}
