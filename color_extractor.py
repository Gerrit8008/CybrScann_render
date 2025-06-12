#!/usr/bin/env python3
"""
Color extraction utility for auto-detecting website colors
"""
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import colorsys
from collections import Counter

class ColorExtractor:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def extract_colors_from_url(self, url):
        """Extract colors from a website"""
        try:
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Fetch the webpage
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            colors = {
                'primary': None,
                'secondary': None,
                'accent': None,
                'background': '#ffffff',
                'text': '#000000'
            }
            
            # Extract colors from various sources
            all_colors = []
            
            # 1. Check meta theme-color
            theme_color = soup.find('meta', {'name': 'theme-color'})
            if theme_color and theme_color.get('content'):
                colors['primary'] = theme_color['content']
                all_colors.append(theme_color['content'])
            
            # 2. Check inline styles
            for element in soup.find_all(style=True):
                style = element['style']
                inline_colors = self._extract_colors_from_css(style)
                all_colors.extend(inline_colors)
            
            # 3. Check style tags
            for style_tag in soup.find_all('style'):
                if style_tag.string:
                    css_colors = self._extract_colors_from_css(style_tag.string)
                    all_colors.extend(css_colors)
            
            # 4. Try to fetch external stylesheets
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href')
                if href:
                    try:
                        css_url = urljoin(url, href)
                        css_response = requests.get(css_url, headers=self.headers, timeout=5)
                        if css_response.status_code == 200:
                            css_colors = self._extract_colors_from_css(css_response.text)
                            all_colors.extend(css_colors)
                    except:
                        continue
            
            # 5. Check common branding elements
            # Logo area backgrounds
            for selector in ['header', 'nav', '.header', '.navbar', '.navigation', '#header', '#nav']:
                element = soup.select_one(selector)
                if element and element.get('style'):
                    element_colors = self._extract_colors_from_css(element['style'])
                    all_colors.extend(element_colors)
            
            # Button colors
            for button in soup.find_all(['button', 'a'], class_=re.compile(r'btn|button', re.I)):
                if button.get('style'):
                    button_colors = self._extract_colors_from_css(button['style'])
                    all_colors.extend(button_colors)
            
            # Process and select best colors
            if all_colors:
                color_groups = self._group_similar_colors(all_colors)
                sorted_groups = sorted(color_groups.items(), key=lambda x: len(x[1]), reverse=True)
                
                # Assign colors based on frequency and characteristics
                for i, (representative, group) in enumerate(sorted_groups[:5]):
                    if not colors['primary'] and self._is_brand_color(representative):
                        colors['primary'] = representative
                    elif not colors['secondary'] and representative != colors['primary']:
                        colors['secondary'] = representative
                    elif not colors['accent'] and self._is_accent_color(representative):
                        colors['accent'] = representative
            
            # Fallback to generated colors if needed
            if not colors['primary']:
                colors['primary'] = '#007bff'
            if not colors['secondary']:
                colors['secondary'] = self._generate_secondary_color(colors['primary'])
            if not colors['accent']:
                colors['accent'] = self._generate_accent_color(colors['primary'])
            
            return colors
            
        except Exception as e:
            print(f"Error extracting colors: {e}")
            # Return default colors on error
            return {
                'primary': '#007bff',
                'secondary': '#6c757d',
                'accent': '#28a745',
                'background': '#ffffff',
                'text': '#000000'
            }
    
    def _extract_colors_from_css(self, css_text):
        """Extract color values from CSS text"""
        colors = []
        
        # Regex patterns for different color formats
        hex_pattern = r'#(?:[0-9a-fA-F]{3}){1,2}\b'
        rgb_pattern = r'rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)'
        rgba_pattern = r'rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*[\d.]+\s*\)'
        
        # Find hex colors
        hex_colors = re.findall(hex_pattern, css_text)
        colors.extend(hex_colors)
        
        # Find RGB colors and convert to hex
        rgb_matches = re.findall(rgb_pattern, css_text)
        for r, g, b in rgb_matches:
            hex_color = f'#{int(r):02x}{int(g):02x}{int(b):02x}'
            colors.append(hex_color)
        
        # Find RGBA colors and convert to hex
        rgba_matches = re.findall(rgba_pattern, css_text)
        for r, g, b in rgba_matches:
            hex_color = f'#{int(r):02x}{int(g):02x}{int(b):02x}'
            colors.append(hex_color)
        
        return colors
    
    def _hex_to_rgb(self, hex_color):
        """Convert hex color to RGB tuple"""
        hex_color = hex_color.lstrip('#')
        if len(hex_color) == 3:
            hex_color = ''.join([c*2 for c in hex_color])
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    
    def _rgb_to_hex(self, rgb):
        """Convert RGB tuple to hex color"""
        return f'#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}'
    
    def _color_distance(self, color1, color2):
        """Calculate distance between two colors"""
        rgb1 = self._hex_to_rgb(color1)
        rgb2 = self._hex_to_rgb(color2)
        return sum((a - b) ** 2 for a, b in zip(rgb1, rgb2)) ** 0.5
    
    def _group_similar_colors(self, colors, threshold=50):
        """Group similar colors together"""
        groups = {}
        
        for color in colors:
            # Skip invalid colors
            if not color or color == 'transparent' or color == 'inherit':
                continue
            
            # Find similar existing group
            found_group = False
            for representative in groups:
                if self._color_distance(color, representative) < threshold:
                    groups[representative].append(color)
                    found_group = True
                    break
            
            # Create new group if no similar color found
            if not found_group:
                groups[color] = [color]
        
        return groups
    
    def _is_brand_color(self, hex_color):
        """Check if color is likely a brand color (not too light or dark)"""
        rgb = self._hex_to_rgb(hex_color)
        # Convert to HSL to check lightness
        h, l, s = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
        # Brand colors are usually not too light or too dark
        return 0.2 < l < 0.8 and s > 0.3
    
    def _is_accent_color(self, hex_color):
        """Check if color is likely an accent color (bright/saturated)"""
        rgb = self._hex_to_rgb(hex_color)
        h, l, s = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
        # Accent colors are usually bright and saturated
        return s > 0.5 and l > 0.4
    
    def _generate_secondary_color(self, primary_hex):
        """Generate a secondary color based on primary"""
        rgb = self._hex_to_rgb(primary_hex)
        h, l, s = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
        
        # Darken slightly for secondary
        l = max(0, l - 0.1)
        s = max(0, s - 0.1)
        
        rgb_new = colorsys.hls_to_rgb(h, l, s)
        return self._rgb_to_hex(tuple(int(c * 255) for c in rgb_new))
    
    def _generate_accent_color(self, primary_hex):
        """Generate an accent color based on primary"""
        rgb = self._hex_to_rgb(primary_hex)
        h, l, s = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
        
        # Rotate hue for complementary color
        h = (h + 0.5) % 1.0
        # Increase saturation for accent
        s = min(1.0, s + 0.2)
        
        rgb_new = colorsys.hls_to_rgb(h, l, s)
        return self._rgb_to_hex(tuple(int(c * 255) for c in rgb_new))