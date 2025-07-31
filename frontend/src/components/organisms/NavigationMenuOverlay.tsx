'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { X } from 'lucide-react';

interface NavigationMenuOverlayProps {
  onClose: () => void;
}

const navigationItems = [
  { name: 'Dashboard', href: '/dashboard' },
  { name: 'Target Profile', href: '/target-profile' },
  { name: 'Passive Recon', href: '/stages/passive-recon' },
  { name: 'Active Recon', href: '/stages/active-recon' },
  { name: 'Vulnerability Scanning', href: '/stages/vulnerability-scanning' },
  { name: 'Vulnerability Testing', href: '/stages/vulnerability-testing' },
  { name: 'Kill Chain', href: '/stages/kill-chain' },
  { name: 'Report Generation', href: '/stages/report-generation' },
  { name: 'Progress/Results', href: '/progress' },
  { name: 'Database', href: '/database' },
  { name: 'Terminal', href: '/terminal' },
];

export function NavigationMenuOverlay({ onClose }: NavigationMenuOverlayProps) {
  return (
    <motion.div
      initial={{ 
        opacity: 0, 
        y: -20, 
        scale: 0.95,
        transformOrigin: 'top left'
      }}
      animate={{ 
        opacity: 1, 
        y: 0, 
        scale: 1,
        transformOrigin: 'top left'
      }}
      exit={{ 
        opacity: 0, 
        y: -20, 
        scale: 0.95,
        transformOrigin: 'top left'
      }}
      transition={{ 
        duration: 0.4, 
        ease: [0.4, 0.0, 0.2, 1],
        type: "spring",
        stiffness: 300,
        damping: 30
      }}
      className="absolute top-0 left-0 w-72 bg-gray-800 border-r border-gray-700 shadow-2xl z-50 rounded-br-xl"
      style={{ 
        transformOrigin: 'top left',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
      }}
    >
      {/* Close button */}
      <div className="flex justify-end p-4">
        <button
          onClick={onClose}
          className="p-2 rounded-lg hover:bg-gray-700 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label="Close navigation menu"
        >
          <X className="w-5 h-5 text-gray-300" />
        </button>
      </div>

      {/* Navigation items */}
      <nav className="px-4 pb-6">
        <ul className="space-y-1">
          {navigationItems.map((item, index) => (
            <motion.li 
              key={item.name}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ 
                delay: index * 0.05,
                duration: 0.3,
                ease: "easeOut"
              }}
            >
              <Link
                href={item.href}
                onClick={onClose}
                className="block px-4 py-3 rounded-lg text-gray-300 hover:bg-gray-700 hover:text-white transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 hover:shadow-md"
              >
                {item.name}
              </Link>
            </motion.li>
          ))}
        </ul>
      </nav>
    </motion.div>
  );
} 