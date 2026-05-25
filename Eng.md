<p align="center">
  <a href="https://github.com/NatsuFlatWhite/Raycipy-Emulator">한국어</a>
  |
  <b>English</b>
</p>

# Raycipy-Emulator

A Python-based server emulator for running the Raycity v1.325 client, released on February 8, 2007.<br>
This is not a complete game server. It only implements some packets and is intended for **non-commercial purposes, mainly for exploring the game world and recreating nostalgic memories**.<br>
There are still many bugs, and many systems are not functional yet.

## Introduction

<p align="center">
  <img src="./Raycity_20260523_1408_001.png" alt="스크린샷" width="100%">
  <br>
  <sup>Dogok-dong village before the major redesign</sup>
</p>

v1.325 is a client version from about two months after the game's official service began.  
It contains many systems that are different from the later versions of the game, and it is the last version before the optimization patch that reduced field texture quality and overall details.

This emulator was created for people who want to revisit or experience Raycity from that early period.

## How to Run

[Download Client](https://drive.google.com/file/d/1ZnlqomkJ58C7djYhDAkFgFsNB7RA_zRK/view?usp=sharing)

Run the server through `main.py`, then launch the game with `Raycity.exe`.

At the login stage, enter any ID you want to use and connect to the server.  
An account will be created automatically.  
Created accounts are saved in `Raycity_db.json`.

## Features

- HTTP
  - Serves `serverlist.xml`.
- Login
  - Login handling
  - Character creation/deletion/selection
  - Vehicle list and vehicle information retrieval
  - Inventory retrieval
  - Shop item purchase handling
  - Partial inventory item movement/equipment handling
- Game
  - Agent handling
  - Partial field entry/movement handling
  - Partial inventory/shop/item handling
  - TimeSync / KeepAlive
  - Account state updates
- UDP
  - UDP Echo
  - Field entry-related responses
  - Partial TimeSync handling
- DB
  - Default save path: `data/Raycity_db.json`
  - Stores characters, vehicles, inventory, items, and more
