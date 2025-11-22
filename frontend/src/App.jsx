// dMail v2 UI update: use append-only mailbox indexes + resolver roots.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import {
  appendInboxEntry,
  appendSentEntry,
  decryptEmail,
  encryptEmail,
  fetchAttachment,
  synapseFetch,
  synapseUpload,
  loadMailboxFromCid,
  createEmptyCalendar,
  appendCalendarEvent,
  loadCalendarFromCid as loadCalendarFromCidFile,
  persistCalendar,
  setMailboxUploadResult,
  setMailboxRootToEns,
  getCalendarUploadResult,
  setCalendarUploadResult,
  generateCalendarIcs,
  resolvePublicKey,
  resolveMailboxRoot,
  updateResolverMailboxRoot,
  normalizeMailboxRoot,
  getMailboxIndexPointer,
  signEnvelope,
  computeEnvelopeMetadataHash,
  verifyEnvelopeSignature,
  getMailboxEntries,
  ensureRegisteredIdentity,
  normalizeServiceUrl,
  setStorageServiceUrl,
} from '@dmail/core'

import CalendarSidebar from './components/calendar/CalendarSidebar'
import EventModal from './components/calendar/EventModal'

import './App.css'
import { clearIdentityCache, getOrCreateIdentityCached } from './utils/identityCache'

const IDENTITY_REGISTRATION_CACHE_KEY = 'dmail_registered_identity_cache'

function readIdentityRegistrationCache() {
  if (typeof window === 'undefined') return {}
  const storage = window.localStorage
  try {
    const raw = storage.getItem(IDENTITY_REGISTRATION_CACHE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    return typeof parsed === 'object' && parsed ? parsed : {}
  } catch {
    return {}
  }
}

function writeIdentityRegistrationCache(cache) {
  if (typeof window === 'undefined') return
  const storage = window.localStorage
  try {
    storage.setItem(IDENTITY_REGISTRATION_CACHE_KEY, JSON.stringify(cache))
  } catch (error) {
    console.warn('Failed to persist identity registration cache', error)
  }
}

const FALLBACK_SEPOLIA_RPC_URL = 'https://ethereum-sepolia-rpc.publicnode.com'
const SEPOLIA_CHAIN_ID_HEX = '0xaa36a7'
function stringToBase64(value) {
  if (typeof window !== 'undefined' && window.btoa) {
    return window.btoa(unescape(encodeURIComponent(value)))
  }
  if (typeof globalThis !== 'undefined' && globalThis.Buffer) {
    return globalThis.Buffer.from(value, 'utf8').toString('base64')
  }
  throw new Error('Base64 encoding is not supported in this environment')
}

function getBrowserHostname() {
  if (typeof window !== 'undefined' && window.location) {
    return window.location.hostname
  }
  return undefined
}

function App() {
  const [walletAddress, setWalletAddress] = useState(null)
  const [ensName, setEnsName] = useState(null)
  const [provider, setProvider] = useState(null)
  const [statusMessage, setStatusMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [identityPublicKey, setIdentityPublicKey] = useState(null)
  const [mailboxUploadResult, setMailboxUploadResultState] = useState(null)
  const [mailboxRoot, setMailboxRoot] = useState(null)
  const mailboxRootRef = useRef(null)
  const [mailboxEntries, setMailboxEntries] = useState([])
  const [sentEntries, setSentEntries] = useState([])
  const [selectedEmails, setSelectedEmails] = useState([]) // Track selected emails for deletion
  const manualDisconnectRef = useRef(false) // Track manual disconnect to prevent auto-reconnect
  
  // Keep ref in sync with state
  useEffect(() => {
    mailboxRootRef.current = mailboxRoot
  }, [mailboxRoot])
  const [loadingInbox, setLoadingInbox] = useState(false)
  const [selectedEmail, setSelectedEmail] = useState(null)
  const [sending, setSending] = useState(false)
  const [showCompose, setShowCompose] = useState(false)
  const [activeView, setActiveView] = useState('inbox')
  const [searchQuery, setSearchQuery] = useState('')
  const [calendarFullPage, setCalendarFullPage] = useState(false)
  const [fetchingPubKey, setFetchingPubKey] = useState(false)
  const [pubKeyFetchError, setPubKeyFetchError] = useState(null)
  const [showManualPubKey, setShowManualPubKey] = useState(false)
  const [composeState, setComposeState] = useState({
    to: '',
    subject: '',
    message: '',
    recipientPublicKey: '',
    attachments: [],
  })
  const [calendarEvents, setCalendarEvents] = useState([])
  const [calendarUploadResult, setCalendarUploadResultState] = useState(null)
  const calendarUploadResultRef = useRef(null)
  const [calendarLoading, setCalendarLoading] = useState(false)
  const [calendarError, setCalendarError] = useState('')
  const [showEventModal, setShowEventModal] = useState(false)
  const [savingEvent, setSavingEvent] = useState(false)
  const [identityDeriving, setIdentityDeriving] = useState(false)
  const [identityStatusMessage, setIdentityStatusMessage] = useState('')
  const identityMaterialRef = useRef(null)
  const identityEnsRef = useRef(null)
  const identityRegistrationCacheRef = useRef(readIdentityRegistrationCache())
  
  // Keep calendar upload result ref in sync with state
  useEffect(() => {
    calendarUploadResultRef.current = calendarUploadResult
  }, [calendarUploadResult])

  const evaluateEntrySignature = useCallback(
    (entry) => {
      if (!entry?.signature || !entry?.signerPublicKey) {
        return null
      }
      try {
        const metadataHash = computeEnvelopeMetadataHash(entry)
        const valid = verifyEnvelopeSignature(entry.signerPublicKey, entry.signature, metadataHash)
        return valid
      } catch (error) {
        console.warn('Failed to verify email signature for entry', entry?.messageId ?? entry?.cid, error)
        return false
      }
    },
    []
  )

  const annotateEntriesWithSignature = useCallback(
    (entries) =>
      entries.map((entry) => ({
        ...entry,
        _signatureValid: evaluateEntrySignature(entry),
      })),
    [evaluateEntrySignature]
  )

  const sepoliaRpcUrl = useMemo(
    () =>
      import.meta.env.VITE_ETH_RPC_URL ??
      import.meta.env.VITE_SEPOLIA_RPC_URL ??
      FALLBACK_SEPOLIA_RPC_URL,
    []
  )

  const ensureSepoliaChain = useCallback(async () => {
    if (!window.ethereum?.request) {
      throw new Error('MetaMask (window.ethereum) not available for ENS operations.')
    }
    const currentChainId = await window.ethereum.request({ method: 'eth_chainId' })
    if (currentChainId === SEPOLIA_CHAIN_ID_HEX) {
      return false
    }
    try {
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: SEPOLIA_CHAIN_ID_HEX }],
      })
      return true
    } catch (switchError) {
      if (switchError?.code === 4902) {
        await window.ethereum.request({
          method: 'wallet_addEthereumChain',
          params: [
            {
              chainId: SEPOLIA_CHAIN_ID_HEX,
              chainName: 'Sepolia test network',
              nativeCurrency: { name: 'Sepolia ETH', symbol: 'ETH', decimals: 18 },
              rpcUrls: [sepoliaRpcUrl],
              blockExplorerUrls: ['https://sepolia.etherscan.io/'],
            },
          ],
        })
        return true
      }
      throw new Error('Please switch MetaMask to the Sepolia testnet before sending mail.')
    }
  }, [sepoliaRpcUrl])

  const ensureProvider = useCallback(async () => {
    if (!window.ethereum) {
      throw new Error('MetaMask (window.ethereum) not available')
    }
    const switched = await ensureSepoliaChain()
    if (!provider || switched) {
      const { BrowserProvider } = await import('ethers')
      const browserProvider = new BrowserProvider(window.ethereum)
      setProvider(browserProvider)
      return browserProvider
    }
    return provider
  }, [provider, ensureSepoliaChain])

  // Create a Sepolia provider specifically for ENS resolution
  const getEnsProvider = useCallback(async () => {
    const { JsonRpcProvider } = await import('ethers')
    return new JsonRpcProvider(sepoliaRpcUrl)
  }, [sepoliaRpcUrl])

  // Function to resolve ENS name for current address
  const resolveEnsName = useCallback(
    async (address) => {
      if (!address) return null

      try {
        // Use Sepolia provider for ENS resolution (ENS names are on Sepolia testnet)
        const ensProvider = await getEnsProvider()
        console.log('Resolving ENS on Sepolia for address:', address)
        
        const name = await ensProvider.lookupAddress(address)
        console.log('ENS reverse lookup result:', name)
        
        if (name) {
          // Verify forward resolution
          try {
            const resolvedAddress = await ensProvider.resolveName(name)
            if (resolvedAddress && resolvedAddress.toLowerCase() === address.toLowerCase()) {
              console.log('✓ ENS name verified:', name, '->', resolvedAddress)
              return name
            } else {
              console.warn('⚠ ENS forward resolution mismatch:', name, 'resolved to', resolvedAddress, 'expected', address)
              return name // Still return it, just warn
            }
          } catch (verifyError) {
            console.warn('⚠ Failed to verify ENS name:', verifyError)
            return name // Still return it if reverse lookup worked
          }
        } else {
          console.warn('⚠ No reverse ENS record found for:', address)
          return null
        }
      } catch (error) {
        console.error('❌ Failed to lookup ENS name:', error)
        return null
      }
    },
    [getEnsProvider]
  )

  const markIdentityRegistered = useCallback((identifier, publicKey) => {
    if (!identifier || !publicKey) return
    identityRegistrationCacheRef.current = identityRegistrationCacheRef.current ?? {}
    if (identityRegistrationCacheRef.current[identifier] === publicKey) return
    identityRegistrationCacheRef.current[identifier] = publicKey
    writeIdentityRegistrationCache(identityRegistrationCacheRef.current)
  }, [])

  const isIdentityRegisteredInSession = useCallback((identifier, publicKey) => {
    if (!identifier || !publicKey) return false
    return identityRegistrationCacheRef.current?.[identifier] === publicKey
  }, [])

  const ensureRegisteredIdentityIfNeeded = useCallback(
    async (targetEns, derivedIdentity, signer) => {
      if (!targetEns || !derivedIdentity?.x25519PublicBase64 || !targetEns.endsWith('.eth')) {
        return false
      }
      if (isIdentityRegisteredInSession(targetEns, derivedIdentity.x25519PublicBase64)) {
        return false
      }
      try {
        const ensProvider = await getEnsProvider()
        if (ensProvider) {
          try {
            const existing = await resolvePublicKey(targetEns, {
              provider: ensProvider,
              ensName: targetEns,
            })
            if (existing === derivedIdentity.x25519PublicBase64) {
              markIdentityRegistered(targetEns, derivedIdentity.x25519PublicBase64)
              return false
            }
          } catch (lookupError) {
            console.warn('Resolver lookup failed while checking identity registration', lookupError)
          }
        }
        await ensureRegisteredIdentity(targetEns, derivedIdentity.x25519PublicBase64, signer)
        markIdentityRegistered(targetEns, derivedIdentity.x25519PublicBase64)
        return true
      } catch (registrationError) {
        console.warn('Failed to register identity with resolver', registrationError)
        throw registrationError
      }
    },
    [getEnsProvider, isIdentityRegisteredInSession, markIdentityRegistered]
  )

  const deriveIdentityMaterial = useCallback(
    async (ensOverride) => {
      const targetIdentifier = ensOverride ?? ensName ?? walletAddress ?? null
      if (!walletAddress) {
        identityMaterialRef.current = null
        identityEnsRef.current = null
        setIdentityPublicKey(null)
        setIdentityStatusMessage('')
        return null
      }
      try {
        setIdentityDeriving(true)
        setIdentityStatusMessage('Generating dMail identity...')
        const providerInstance = await ensureProvider()
        const signer = await providerInstance.getSigner()
        let signerAddress = null
        try {
          signerAddress = (await signer.getAddress())?.toLowerCase() ?? null
        } catch (addressError) {
          console.warn('Unable to read signer address for identity cache key', addressError)
        }
        const derived = await getOrCreateIdentityCached({
          signer,
          account: signerAddress ?? walletAddress?.toLowerCase(),
          domain: getBrowserHostname(),
        })
        identityMaterialRef.current = {
          privateKey: derived.x25519PrivateBase64,
          publicKey: derived.x25519PublicBase64,
          senderStaticSymKey: derived.senderStaticSymKeyBase64,
          signingKey: derived.signingKeyBase64,
          signingPublicKey: derived.signingPublicKeyBase64,
        }
        identityEnsRef.current = targetIdentifier
        setIdentityPublicKey(derived.x25519PublicBase64)
        if (targetIdentifier && isIdentityRegisteredInSession(targetIdentifier, derived.x25519PublicBase64)) {
          setIdentityStatusMessage('Identity already registered for this session.')
        } else if (targetIdentifier) {
          try {
            setIdentityStatusMessage('Checking resolver registration...')
            const registered = await ensureRegisteredIdentityIfNeeded(
              targetIdentifier,
              derived,
              signer
            )
            setIdentityStatusMessage(
              registered
                ? 'Identity registered with ENS resolver.'
                : 'Identity stored in your browser.'
            )
          } catch (registrationError) {
            setIdentityStatusMessage(
              registrationError.message ?? 'Resolver registration failed.'
            )
          }
        } else {
          setIdentityStatusMessage('Identity stored in your browser.')
        }
        return identityMaterialRef.current
      } catch (error) {
        console.warn('Failed to derive identity from wallet', error)
        setIdentityStatusMessage(error.message ?? 'Failed to derive identity.')
        return null
      } finally {
        setIdentityDeriving(false)
      }
    },
    [walletAddress, ensName, ensureProvider, ensureRegisteredIdentityIfNeeded, isIdentityRegisteredInSession]
  )

  const ensureIdentityMaterial = useCallback(
    async (ensOverride) => {
      const targetEns = ensOverride ?? ensName ?? walletAddress ?? null
      if (
        identityMaterialRef.current &&
        identityMaterialRef.current.publicKey &&
        identityEnsRef.current === targetEns
      ) {
        return identityMaterialRef.current
      }
      return await deriveIdentityMaterial(targetEns)
    },
    [deriveIdentityMaterial, ensName]
  )

  const handleRegenerateIdentity = useCallback(async () => {
    if (!walletAddress) {
      setStatusMessage('Connect wallet to derive identity first.')
      return
    }
    const domain = getBrowserHostname()
    clearIdentityCache(walletAddress?.toLowerCase(), domain)
    identityMaterialRef.current = null
    identityEnsRef.current = null
    setIdentityPublicKey(null)
    await deriveIdentityMaterial(ensName)
  }, [walletAddress, ensName, deriveIdentityMaterial])

  // Listen for account changes and re-resolve ENS
  useEffect(() => {
    if (!window.ethereum || !walletAddress) return

    const handleAccountsChanged = async (accounts) => {
      if (accounts.length > 0 && accounts[0] !== walletAddress) {
        console.log('Account changed to:', accounts[0])
        const newAddress = accounts[0]
        setWalletAddress(newAddress)
        
        // Resolve ENS name using Sepolia provider
        const name = await resolveEnsName(newAddress)
        setEnsName(name)
      } else if (accounts.length === 0) {
        console.log('Wallet disconnected')
        setWalletAddress(null)
        setEnsName(null)
      }
    }

    window.ethereum.on('accountsChanged', handleAccountsChanged)

    return () => {
      window.ethereum?.removeListener('accountsChanged', handleAccountsChanged)
    }
  }, [walletAddress, resolveEnsName])

  useEffect(() => {
    if (!walletAddress) {
      identityMaterialRef.current = null
      identityEnsRef.current = null
      setIdentityPublicKey(null)
      return
    }
    void deriveIdentityMaterial(ensName)
  }, [walletAddress, ensName, deriveIdentityMaterial])
  
  // Separate effect to auto-refresh inbox after wallet connection
  useEffect(() => {
    if (!walletAddress || !identityPublicKey) {
      return
    }
    console.log('[autoRefresh] Wallet connected and identity derived, refreshing inbox...')
    void refreshInbox()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [walletAddress, identityPublicKey])
  
  // Update status message when view changes to show section-specific count
  useEffect(() => {
    if (!walletAddress) return
    const currentCount = activeView === 'sent' ? sentEntries.length : mailboxEntries.length
    const sectionName = activeView === 'sent' ? 'sent' : 'inbox'
    if (currentCount > 0) {
      setStatusMessage(`Loaded ${currentCount} ${sectionName} email(s)`)
    }
  }, [activeView, mailboxEntries.length, sentEntries.length, walletAddress])

  useEffect(() => {
    if (typeof window === 'undefined' || !window.ethereum) {
      return
    }
    let cancelled = false
    const autoConnect = async () => {
      // Skip auto-connect if user manually disconnected
      if (manualDisconnectRef.current) {
        console.log('[autoConnect] Skipping - user manually disconnected')
        return
      }
      try {
        const { BrowserProvider } = await import('ethers')
        const browserProvider = new BrowserProvider(window.ethereum)
        const accounts = await browserProvider.send('eth_accounts', [])
        if (!accounts?.length || cancelled) {
          return
        }
        const address = accounts[0]
        setWalletAddress(address)
        const resolvedName = await resolveEnsName(address)
        setEnsName(resolvedName)
        await deriveIdentityMaterial(resolvedName)
        // The useEffect watching walletAddress will trigger refreshInbox
      } catch (error) {
        console.warn('Auto-connect skipped', error)
      }
    }
    void autoConnect()
    return () => {
      cancelled = true
    }
  }, [deriveIdentityMaterial, resolveEnsName])

  const connectWallet = useCallback(async () => {
    try {
      setErrorMessage('')
      manualDisconnectRef.current = false // Reset disconnect flag to allow auto-reconnect
      const browserProvider = await ensureProvider()
      const accounts = await browserProvider.send('eth_requestAccounts', [])
      const address = accounts?.[0]
      if (!address) throw new Error('No accounts returned from provider')
      setWalletAddress(address)
      
      // Resolve ENS name using Sepolia provider (ENS names are on Sepolia testnet)
      const resolvedName = await resolveEnsName(address)
      setEnsName(resolvedName)
      
      // Don't show toast - status is shown in navbar
      return browserProvider
    } catch (error) {
      console.error(error)
      setErrorMessage(error.message ?? 'Failed to connect wallet')
      return null
    }
  }, [ensureProvider, resolveEnsName])

  const handleDisconnectWallet = useCallback(() => {
    const domain = getBrowserHostname()
    if (walletAddress) {
      try {
        clearIdentityCache(walletAddress.toLowerCase(), domain)
      } catch (cacheError) {
        console.warn('Failed to clear identity cache on disconnect', cacheError)
      }
    }
    manualDisconnectRef.current = true // Prevent auto-reconnect
    identityMaterialRef.current = null
    identityEnsRef.current = null
    setWalletAddress(null)
    setEnsName(null)
    setProvider(null)
    setIdentityPublicKey(null)
    setMailboxRoot(null)
    setMailboxUploadResultState(null)
    setMailboxEntries([])
    setSentEntries([])
    setSelectedEmail(null)
    setComposeState({ to: '', subject: '', message: '', recipientPublicKey: '', attachments: [] })
    setCalendarEvents([])
    setCalendarUploadResultState(null)
    setCalendarError('')
    setStatusMessage('Wallet disconnected')
    setErrorMessage('')
  }, [walletAddress])

  const updateCompose = (changes) => {
    setComposeState((prev) => ({
      ...prev,
      ...changes,
    }))
  }

  // Auto-fetch public key from ENS when recipient changes
  const fetchRecipientPublicKey = useCallback(
    async (ensName) => {
      if (!ensName || !ensName.endsWith('.eth')) {
        setPubKeyFetchError(null)
        setShowManualPubKey(false)
        updateCompose({ recipientPublicKey: '' })
        return
      }

      setFetchingPubKey(true)
      setPubKeyFetchError(null)
      setShowManualPubKey(false)

      try {
        const ensProvider = await getEnsProvider()
        const publicKey =
          (await resolvePublicKey(ensName, { provider: ensProvider, ensName })) ?? null
        
        if (publicKey) {
          updateCompose({ recipientPublicKey: publicKey })
          setPubKeyFetchError(null)
        } else {
          setPubKeyFetchError(
            `No resolver profile found for ${ensName}. Ask the recipient to open dMail v2 once to onboard automatically.`
          )
          setShowManualPubKey(true)
          updateCompose({ recipientPublicKey: '' })
        }
      } catch (error) {
        console.warn('Failed to fetch public key from ENS:', error)
        setPubKeyFetchError(`Could not fetch public key for ${ensName}. You can enter it manually.`)
        setShowManualPubKey(true)
        updateCompose({ recipientPublicKey: '' })
      } finally {
        setFetchingPubKey(false)
      }
    },
    [getEnsProvider]
  )

  const refreshInbox = useCallback(async () => {
    setLoadingInbox(true)
    setErrorMessage('')
    try {
      await ensureProvider()
      const ensProvider = await getEnsProvider()
      const targetEns =
        ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)
      const ownerIdentifier = targetEns ?? walletAddress
      
      // Fetch mailbox root from resolver (with ENS fallback)
      console.log('[refreshInbox] Fetching mailbox root for:', ownerIdentifier)
      const mailboxRootResponse = await resolveMailboxRoot(ownerIdentifier, {
        provider: ensProvider,
      })
      console.log('[refreshInbox] Raw mailbox root response:', mailboxRootResponse)
      
      const normalizedRoot = normalizeMailboxRoot(mailboxRootResponse, { owner: ownerIdentifier })
      
      console.log('[refreshInbox] Normalized mailbox root:', {
        owner: ownerIdentifier,
        normalizedRoot,
        hasInbox: !!normalizedRoot?.inbox,
        hasSent: !!normalizedRoot?.sent,
      })
      
      setMailboxRoot(normalizedRoot)

      const inboxPointer = getMailboxIndexPointer(normalizedRoot, 'inbox')
      const sentPointer = getMailboxIndexPointer(normalizedRoot, 'sent')
      
      console.log('[refreshInbox] Mailbox pointers:', {
        inboxCid: inboxPointer?.cid,
        sentCid: sentPointer?.cid,
      })
      
      setMailboxUploadResultState(inboxPointer ?? null)

      if (!inboxPointer?.cid && !sentPointer?.cid) {
        setMailboxEntries([])
        setSentEntries([])
        setStatusMessage('No mailbox found for this account yet')
        return
      }

      const [inboxMailbox, sentMailbox] = await Promise.all([
        inboxPointer?.cid
          ? loadMailboxFromCid(inboxPointer, { optional: true })
          : Promise.resolve(null),
        sentPointer?.cid
          ? loadMailboxFromCid(sentPointer, { optional: true })
          : Promise.resolve(null),
      ])

      const inboxEntriesList = annotateEntriesWithSignature(getMailboxEntries(inboxMailbox))
      const sentEntriesList = annotateEntriesWithSignature(getMailboxEntries(sentMailbox))
      
      console.log('[refreshInbox] Loaded entries:', {
        inboxCount: inboxEntriesList.length,
        sentCount: sentEntriesList.length,
        inboxCids: inboxEntriesList.map(e => ({ cid: e.cid, subject: e.subjectPreview, timestamp: e.timestamp })),
        sentCids: sentEntriesList.map(e => ({ cid: e.cid, subject: e.subjectPreview, timestamp: e.timestamp })),
        mailboxRoot: normalizedRoot,
      })
      
      // Use only the loaded entries (no merging with old data)
      setMailboxEntries(inboxEntriesList)
      setSentEntries(sentEntriesList)
      
      // Show section-specific count based on active view
      const inboxCount = inboxEntriesList.length
      const sentCount = sentEntriesList.length
      const currentViewCount = activeView === 'sent' ? sentCount : inboxCount
      const sectionName = activeView === 'sent' ? 'sent' : 'inbox'
      setStatusMessage(`Loaded ${currentViewCount} ${sectionName} email(s)`)
    } catch (error) {
      console.error(error)
      setErrorMessage(error.message ?? 'Failed to load mailbox')
    } finally {
      setLoadingInbox(false)
    }
  }, [ensureProvider, ensName, getEnsProvider, walletAddress, annotateEntriesWithSignature, activeView])

  const refreshCalendar = useCallback(async () => {
    if (!walletAddress && !ensName) return

    setCalendarLoading(true)
    setCalendarError('')
    try {
      const ensProvider = await getEnsProvider()
      await ensureProvider()
      const targetEns =
        ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)
      if (!targetEns) {
        setCalendarEvents([])
        setCalendarUploadResultState(null)
        return
      }

      // Fetch calendar upload result from ENS
      const uploadResult = await getCalendarUploadResult(targetEns, { provider: ensProvider })

      if (!uploadResult?.cid || !uploadResult?.pieceCid) {
        console.log('[refreshCalendar] No calendar found in ENS')
        setCalendarEvents([])
        setCalendarUploadResultState(null)
        setStatusMessage('No calendar found. Create an event to start a new calendar.')
        return
      }

      console.log('[refreshCalendar] Fetched calendar from ENS:', {
        cid: uploadResult.cid,
      })

      const calendar = await loadCalendarFromCidFile(uploadResult, { optional: true })
      setCalendarEvents(calendar?.events ?? [])
    } catch (error) {
      console.error(error)
      setCalendarError(error.message ?? 'Failed to load calendar')
    } finally {
      setCalendarLoading(false)
    }
  }, [walletAddress, ensName, getEnsProvider, ensureProvider])

  useEffect(() => {
    if (!walletAddress && !ensName) return
    void refreshInbox()
  }, [walletAddress, ensName, refreshInbox])

  useEffect(() => {
    if (!walletAddress && !ensName) return
    void refreshCalendar()
  }, [walletAddress, ensName, refreshCalendar])

  const openEmail = useCallback(
    async (entry) => {
      setSelectedEmail(null)
      setErrorMessage('')
      if (!identityMaterialRef.current?.privateKey) {
        setErrorMessage('Identity key required to decrypt emails')
        return
      }
      try {
        const folder = entry.folder ?? activeView ?? 'inbox'
        const isSentEntry = folder === 'sent'
        
        // For inbox: use recipient envelope (bodyCid/keyEnvelopesCid)
        // For sent: use sender envelope (senderCopyCid/cidSender)
        let cid, pieceCid, serviceURL, providerId, providerAddress
        
        if (isSentEntry) {
          // Sent folder: use sender envelope
          cid = entry.senderCopyCid ?? entry.cidSender ?? entry.cid
          pieceCid = entry.senderPieceCid ?? entry.pieceCid
          serviceURL = entry.senderServiceURL ?? entry.serviceURL
          providerId = entry.senderProviderId ?? entry.providerId
          providerAddress = entry.senderProviderAddress ?? entry.providerAddress
        } else {
          // Inbox: use recipient envelope
          cid = entry.bodyCid ?? entry.keyEnvelopesCid ?? entry.cidRecipient ?? entry.cid
          pieceCid = entry.recipientPieceCid ?? entry.pieceCid
          serviceURL = entry.serviceURL
          providerId = entry.providerId
          providerAddress = entry.providerAddress
        }

        console.log('[openEmail] Fetching encrypted payload:', {
          folder,
          isSentEntry,
          cid,
          pieceCid,
          bodyCid: entry.bodyCid,
          keyEnvelopesCid: entry.keyEnvelopesCid,
          senderCopyCid: entry.senderCopyCid,
          cidSender: entry.cidSender,
        })

        if (!cid || !pieceCid || !serviceURL) {
          throw new Error(`Email entry missing provider info for ${isSentEntry ? 'sender' : 'recipient'} envelope. Cannot retrieve with Synapse-only mode.`)
        }
        
        const baseInfo = {
          id: providerId,
          address: providerAddress,
          products: {},
        }
        const productKey = 'STORAGE'
        baseInfo.products[productKey] = {
          data: {
            serviceURL: normalizeServiceUrl(serviceURL),
          }
        }
        const providerInfo = baseInfo
        
        const encryptedPayload = await synapseFetch(cid, {
          as: 'json',
          pieceCid,
          providerInfo
        })
        
        console.log('[openEmail] Encrypted payload structure:', {
          keys: Object.keys(encryptedPayload),
          hasRecipientEnvelope: !!encryptedPayload.recipientEnvelope,
          hasSenderEnvelope: !!encryptedPayload.senderEnvelope,
          hasVersion: !!encryptedPayload.version,
          hasCiphertext: !!encryptedPayload.ciphertext,
          hasEphemeralPublicKey: !!encryptedPayload.ephemeralPublicKey,
          version: encryptedPayload.version,
        })
        
        // The fetched payload should be a v2 envelope:
        // 1. Full structure with recipientEnvelope/senderEnvelope (v2)
        // 2. A single envelope with ciphertext + version (v2)
        // decryptEmail will handle both formats automatically
        const payloadToDecrypt = encryptedPayload
        
        if (!encryptedPayload.recipientEnvelope && !encryptedPayload.senderEnvelope && 
            (!encryptedPayload.ciphertext || !encryptedPayload.version)) {
          console.error('[openEmail] Invalid v2 payload structure:', {
            payload: encryptedPayload,
            hasCiphertext: !!encryptedPayload.ciphertext,
            hasVersion: !!encryptedPayload.version,
            keys: Object.keys(encryptedPayload),
          })
          throw new Error('Unable to decrypt: invalid v2 encrypted payload structure. Expected envelope with ciphertext and version, or structure with recipientEnvelope/senderEnvelope.')
        }
        
        // Decrypt email and fetch attachments from Synapse
        console.log('[openEmail] Attempting decryption with key material...')
        const decrypted = await decryptEmail(
          payloadToDecrypt,
          {
            identityPrivateKey: identityMaterialRef.current?.privateKey ?? null,
            senderSecret: identityMaterialRef.current?.privateKey ?? null,
          },
          {
            fetchAttachmentsFromSynapse: true,
          }
        )
        console.log('[openEmail] Decryption successful:', {
          hasSubject: !!decrypted.subject,
          hasMessage: !!decrypted.message,
          attachmentsCount: decrypted.attachments?.length ?? 0,
        })
        let signatureValid = entry._signatureValid ?? null
        if (signatureValid === null && entry.signature && entry.signerPublicKey) {
          try {
            const metadataHash = computeEnvelopeMetadataHash(entry)
            signatureValid = verifyEnvelopeSignature(entry.signerPublicKey, entry.signature, metadataHash)
            if (signatureValid === false) {
              setStatusMessage('⚠️ Email signature invalid')
            }
          } catch (signatureError) {
            console.warn('Failed to verify email signature', signatureError)
          }
        }
        setSelectedEmail({
          entry,
          decrypted,
          encrypted: encryptedPayload,
          signatureValid,
        })
      } catch (error) {
        console.error(error)
        setErrorMessage(error.message ?? 'Failed to decrypt email. Check private key.')
      }
    },
    [activeView]
  )

  const handleAttachments = async (event) => {
    const files = Array.from(event.target.files ?? [])
    const attachments = await Promise.all(
      files.map(async (file) => ({
        filename: file.name,
        mimeType: file.type || 'application/octet-stream',
        data: await readFileAsBase64(file),
      }))
    )
    updateCompose({ attachments })
  }

  const handleShareEvent = useCallback(
    (event) => {
      if (!event) return
      const organizer = ensName ?? walletAddress ?? 'dmail-user'
      const ics = generateCalendarIcs(event, organizer)
      setComposeState({
        to: '',
        subject: `[Invite] ${event.title}`,
        message: `You're invited to ${event.title} on ${new Date(event.startTime).toLocaleString()}${
          event.location ? ` at ${event.location}` : ''
        }.\n\n${event.description ?? ''}`,
        attachments: [
          {
            filename: `${event.title || 'event'}.ics`,
            mimeType: 'text/calendar',
            data: stringToBase64(ics),
          },
        ],
        recipientPublicKey: '',
      })
      setShowCompose(true)
    },
    [ensName, walletAddress]
  )

  const handleDownloadAttachment = useCallback(async (attachment) => {
    try {
      if (!attachment) {
        throw new Error('Attachment is missing')
      }

      let attachmentData = attachment

      const attachmentKey = identityMaterialRef.current?.privateKey || ''

      // If attachment needs to be fetched from Synapse, fetch it first
      if (attachment._needsFetch && attachment.cid && attachment.pieceCid && attachmentKey) {
        setStatusMessage('Fetching attachment from storage...')
        try {
          attachmentData = await fetchAttachment(
            {
              cid: attachment.cid,
              pieceCid: attachment.pieceCid,
              providerInfo: attachment.providerInfo,
              encryptedMetadata: attachment.encryptedMetadata,
            },
            attachmentKey
          )
          // Update the attachment in the selected email to cache it
          if (selectedEmail?.decrypted?.attachments) {
            const updatedAttachments = selectedEmail.decrypted.attachments.map((att) =>
              att.cid === attachment.cid ? attachmentData : att
            )
            setSelectedEmail({
              ...selectedEmail,
              decrypted: {
                ...selectedEmail.decrypted,
                attachments: updatedAttachments,
              },
            })
          }
        } catch (fetchError) {
          console.error('Failed to fetch attachment from Synapse:', fetchError)
          throw new Error(`Failed to fetch attachment: ${fetchError.message}`)
        }
      } else if (attachment._needsFetch && !attachmentKey) {
        throw new Error('Identity key required to decrypt this attachment.')
      }

      if (!attachmentData.data) {
        throw new Error('Attachment data is missing')
      }

      // Decode base64 data
      const base64Data = attachmentData.data
      const binaryString = atob(base64Data)
      const bytes = new Uint8Array(binaryString.length)
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
      }

      // Create blob from bytes
      const blob = new Blob([bytes], { type: attachmentData.mimeType || 'application/octet-stream' })

      // Create download link
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = attachmentData.filename || 'attachment'
      document.body.appendChild(link)
      link.click()

      // Cleanup
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
      setStatusMessage('')
    } catch (error) {
      console.error('Failed to download attachment:', error)
      setErrorMessage(`Failed to download attachment: ${error.message}`)
      setStatusMessage('')
    }
  }, [selectedEmail])

  // Toggle email selection for deletion
  const toggleEmailSelection = useCallback((entry) => {
    const entryKey = entry.messageId ?? entry.cid
    setSelectedEmails((prev) => {
      const isSelected = prev.some((e) => (e.messageId ?? e.cid) === entryKey)
      if (isSelected) {
        return prev.filter((e) => (e.messageId ?? e.cid) !== entryKey)
      } else {
        return [...prev, entry]
      }
    })
  }, [])
  
  // Select/deselect all emails
  const toggleSelectAll = useCallback(() => {
    const source = activeView === 'sent' ? sentEntries : mailboxEntries
    const sorted = [...source].sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0))
    let emails = sorted
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      emails = sorted.filter(
        (entry) =>
          entry.from?.toLowerCase().includes(query) ||
          (Array.isArray(entry.toRecipients)
            ? entry.toRecipients.join(', ').toLowerCase().includes(query)
            : entry.to?.toLowerCase().includes(query)) ||
          entry.subjectPreview?.toLowerCase().includes(query)
      )
    }
    
    if (selectedEmails.length === emails.length) {
      setSelectedEmails([])
    } else {
      setSelectedEmails([...emails])
    }
  }, [selectedEmails.length, activeView, sentEntries, mailboxEntries, searchQuery])
  
  // Delete selected emails
  const handleDeleteSelected = useCallback(async () => {
    if (selectedEmails.length === 0) {
      setErrorMessage('No emails selected')
      return
    }
    
    const confirmDelete = window.confirm(
      `Are you sure you want to delete ${selectedEmails.length} email(s)? This action cannot be undone.`
    )
    if (!confirmDelete) return
    
    try {
      setStatusMessage(`Deleting ${selectedEmails.length} email(s)...`)
      const browserProvider = await ensureProvider()
      const signer = await browserProvider.getSigner()
      const ensProvider = await getEnsProvider()
      const senderEns = ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)
      
      if (!senderEns) {
        throw new Error('ENS name not resolved. Connect wallet first.')
      }
      
      const selectedKeys = selectedEmails.map(e => e.messageId ?? e.cid)
      
      // Filter out deleted emails from current entries
      const newInboxEntries = activeView === 'inbox' 
        ? mailboxEntries.filter(e => !selectedKeys.includes(e.messageId ?? e.cid))
        : mailboxEntries
      const newSentEntries = activeView === 'sent'
        ? sentEntries.filter(e => !selectedKeys.includes(e.messageId ?? e.cid))
        : sentEntries
      
      // Update local state immediately (optimistic update)
      setMailboxEntries(newInboxEntries)
      setSentEntries(newSentEntries)
      setSelectedEmails([])
      setSelectedEmail(null)
      
      // Create new mailbox with remaining emails and upload to ENS
      const currentMailboxRoot = mailboxRootRef.current || { owner: senderEns, version: 2, inbox: null, sent: null }
      const updatedMailboxRoot = { ...currentMailboxRoot }
      
      setStatusMessage('Updating mailbox on ENS...')
      
      // Upload updated inbox if deleting from inbox
      if (activeView === 'inbox') {
        const inboxMailbox = {
          owner: senderEns,
          type: 'inbox',
          version: 2,
          updatedAt: new Date().toISOString(),
          entries: newInboxEntries,
          emails: newInboxEntries,
        }
        const inboxUploadResult = await synapseUpload(JSON.stringify(inboxMailbox, null, 2), {
          filename: 'inbox.json',
          metadata: {
            type: 'dmail-mailbox-inbox',
            owner: senderEns,
          },
        })
        updatedMailboxRoot.inbox = inboxUploadResult
      }
      
      // Upload updated sent if deleting from sent
      if (activeView === 'sent') {
        const sentMailbox = {
          owner: senderEns,
          type: 'sent',
          version: 2,
          updatedAt: new Date().toISOString(),
          entries: newSentEntries,
          emails: newSentEntries,
        }
        const sentUploadResult = await synapseUpload(JSON.stringify(sentMailbox, null, 2), {
          filename: 'sent.json',
          metadata: {
            type: 'dmail-mailbox-sent',
            owner: senderEns,
          },
        })
        updatedMailboxRoot.sent = sentUploadResult
      }
      
      setMailboxRoot(updatedMailboxRoot)
      
      // Update offchain resolver with full mailbox root (includes both inbox and sent pointers)
      try {
        await updateResolverMailboxRoot(senderEns, updatedMailboxRoot)
        console.log('[handleDeleteSelected] Updated offchain resolver with mailbox root')
      } catch (resolverError) {
        console.warn('[handleDeleteSelected] Failed to update offchain resolver:', resolverError)
      }
      
      // Update ENS with both inbox and sent pointers
      try {
        await setMailboxRootToEns(senderEns, updatedMailboxRoot, {
          provider: browserProvider,
          signer,
          wait: false, // Don't wait for blockchain confirmation
        })
        console.log('[handleDeleteSelected] Updated ENS with mailbox root:', {
          inboxCid: updatedMailboxRoot?.inbox?.cid,
          sentCid: updatedMailboxRoot?.sent?.cid,
        })
      } catch (ensError) {
        console.warn('[handleDeleteSelected] Failed to update ENS:', ensError)
      }
      
      const count = activeView === 'sent' ? newSentEntries.length : newInboxEntries.length
      setStatusMessage(`Deleted ${selectedEmails.length} email(s). Refreshing...`)
      
      // Refresh to ensure UI is in sync with resolver/ENS
      await refreshInbox()
    } catch (error) {
      console.error('Failed to delete emails:', error)
      setErrorMessage(error.message ?? 'Failed to delete emails')
      // Revert optimistic update on error
      await refreshInbox()
    }
  }, [selectedEmails, activeView, mailboxEntries, sentEntries, ensName, walletAddress, ensureProvider, getEnsProvider, mailboxRootRef, refreshInbox])

  const handleSaveEvent = useCallback(
    async (eventInput) => {
      setSavingEvent(true)
      setCalendarError('')
      try {
        const ensProvider = await getEnsProvider()
        const browserProvider = (await ensureProvider()) ?? provider
        const signer = await browserProvider.getSigner()
        const ownerEns = ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)
        if (!ownerEns) {
          throw new Error('ENS name not resolved for calendar')
        }

        // Fetch existing calendar from ENS and append to it
        const existingUploadResult = await getCalendarUploadResult(ownerEns, { provider: ensProvider })
        let calendarData
        
        if (existingUploadResult?.cid) {
          console.log('[handleSaveEvent] Loading existing calendar from ENS:', existingUploadResult.cid)
          calendarData = await loadCalendarFromCidFile(existingUploadResult, { optional: true })
        }
        
        if (!calendarData) {
          console.log('[handleSaveEvent] No existing calendar, creating new one')
          calendarData = createEmptyCalendar(ownerEns)
        }

        const updatedCalendar = appendCalendarEvent(calendarData, eventInput)
        console.log('[handleSaveEvent] Appending event to calendar:', {
          existingEventsCount: calendarData.events?.length ?? 0,
          newEventCount: updatedCalendar.events.length,
        })
        const uploadResult = await persistCalendar(updatedCalendar, {
          owner: ownerEns,
          uploadOptions: {
            metadata: {
              type: 'dmail-calendar',
              owner: ownerEns,
            },
          },
        })

        await setCalendarUploadResult(ownerEns, uploadResult, { signer, wait: true })
        setCalendarUploadResultState(uploadResult)
        setCalendarEvents(updatedCalendar.events)
        setShowEventModal(false)
      } catch (error) {
        console.error(error)
        setCalendarError(error.message ?? 'Failed to save event')
      } finally {
        setSavingEvent(false)
      }
    },
    [calendarEvents, ensName, ensureProvider, getEnsProvider, provider, walletAddress]
  )

  const handleSend = useCallback(
    async (event) => {
      event?.preventDefault()
      setSending(true)
      setErrorMessage('')
      setStatusMessage('Encrypting email...')
      try {
        const browserProvider = await ensureProvider()
        const signer = await browserProvider.getSigner()
        const ensProvider = await getEnsProvider()
        const senderEns =
          ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)

        if (!senderEns) {
          throw new Error('ENS name not resolved for connected wallet. Set one before sending.')
        }

        const recipientInput = composeState.to?.trim()
        if (!recipientInput) {
          throw new Error('Recipient ENS name is required')
        }
        const recipientEns = recipientInput
        const normalizedRecipientEns = recipientEns.toLowerCase()
        const normalizedSenderEns = senderEns?.toLowerCase() ?? null
        const isSelfRecipient = normalizedSenderEns && normalizedSenderEns === normalizedRecipientEns

        // Ensure identity is derived first (needed for self-sending)
        const activeIdentity = identityMaterialRef.current ?? (await ensureIdentityMaterial(senderEns))
        if (!activeIdentity) {
          throw new Error('Unable to prepare identity keys. Reconnect wallet and try again.')
        }
        if (!activeIdentity.signingKey || !activeIdentity.signingPublicKey) {
          throw new Error('Identity signing material missing. Reconnect wallet to derive identity again.')
        }

        console.log('[sendEmail] Sender ENS:', senderEns)
        console.log('[sendEmail] Recipient input:', recipientInput)
        console.log('[sendEmail] Is self-recipient?', isSelfRecipient, { normalizedSenderEns, normalizedRecipientEns })
        console.log('[sendEmail] Active identity publicKey:', activeIdentity.publicKey?.substring(0, 30) + '...')

        let recipientPublicKey = null
        
        // Priority 1: If sending to yourself, ALWAYS use your derived identity key (ignore compose form)
        if (isSelfRecipient) {
          recipientPublicKey = activeIdentity.publicKey
          console.log('[sendEmail] ✓ Sending to self, using derived identity key (v2 X25519):', recipientPublicKey?.substring(0, 30) + '...')
        }
        // Priority 2: Use manually entered key from compose form
        else if (composeState.recipientPublicKey?.trim()) {
          recipientPublicKey = composeState.recipientPublicKey.trim()
          console.log('[sendEmail] Using manually entered public key from compose form:', recipientPublicKey?.substring(0, 30) + '...')
        }
        // Priority 3: Resolve from ENS/resolver
        else {
          console.log('[sendEmail] Resolving public key for recipient:', recipientEns)
          recipientPublicKey =
            (await resolvePublicKey(recipientEns, {
              provider: ensProvider,
              ensName: recipientEns,
              disableEnsFallback: true,
            })) || import.meta.env.VITE_RECIPIENT_PUBLIC_KEY
          console.log('[sendEmail] Resolved public key:', recipientPublicKey?.substring(0, 30) + '...')
        }

        if (!recipientPublicKey) {
          throw new Error(
            `Recipient public key missing. Ask ${recipientEns} to open dMail v2 once or provide a manual key.`
          )
        }

        const normalizedRecipientKey = recipientPublicKey.trim()
        const looksLikeLegacyKey =
          normalizedRecipientKey.startsWith('0x04') ||
          (/^0x[0-9a-fA-F]+$/.test(normalizedRecipientKey) ||
            (/^[0-9a-fA-F]+$/.test(normalizedRecipientKey) &&
              normalizedRecipientKey.length >= 66))

        console.log('[sendEmail] Recipient key validation:', {
          key: normalizedRecipientKey.substring(0, 30) + '...',
          looksLikeLegacyKey,
          startsWithHex: normalizedRecipientKey.startsWith('0x'),
          length: normalizedRecipientKey.length
        })

        if (looksLikeLegacyKey) {
          throw new Error(
            `Recipient ${recipientEns} is still using the legacy dMail key. Ask them to open dMail v2 so their resolver publishes the new X25519 key.`
          )
        }

        recipientPublicKey = normalizedRecipientKey

        const timestamp = Date.now()
        const subjectPreview = composeState.subject?.slice(0, 120) ?? ''
        const attachmentSummaries = composeState.attachments.map((attachment, index) => ({
          filename: attachment.filename || `attachment-${index + 1}`,
          mimeType: attachment.mimeType || 'application/octet-stream',
        }))
        
        // Upload attachments to Synapse if any
        if (composeState.attachments.length > 0) {
          setStatusMessage(`Uploading ${composeState.attachments.length} attachment(s) to Filecoin storage...`)
        }
        
        const encryptedEmail = await encryptEmail(
          {
            from: senderEns,
            to: recipientEns,
            subject: composeState.subject,
            message: composeState.message,
            attachments: composeState.attachments,
            timestamp,
          },
          recipientPublicKey,
          {
            uploadAttachmentsToSynapse: true,
            senderIdentity: activeIdentity,
          }
        )

        let recipientUpload = null
        let senderUpload = null
        if (encryptedEmail?.version >= 2 && encryptedEmail?.recipientEnvelope) {
          // OPTIMIZATION: Upload both envelopes in parallel instead of sequentially
          setStatusMessage('Uploading encrypted email copies to Filecoin storage...')
          const uploadPromises = [
            synapseUpload(encryptedEmail.recipientEnvelope, {
              filename: `email-${senderEns}-${timestamp}.json`,
              metadata: {
                type: 'dmail-email-recipient',
                messageId: encryptedEmail.messageId,
              },
            })
          ]
          
          if (encryptedEmail.senderEnvelope) {
            uploadPromises.push(
              synapseUpload(encryptedEmail.senderEnvelope, {
                filename: `email-${senderEns}-sent-${timestamp}.json`,
                metadata: {
                  type: 'dmail-email-sender',
                  messageId: encryptedEmail.messageId,
                },
              })
            )
          }
          
          const uploads = await Promise.all(uploadPromises)
          recipientUpload = uploads[0]
          senderUpload = uploads[1] || null
        } else {
          setStatusMessage('Uploading encrypted email to Filecoin storage...')
          recipientUpload = await synapseUpload(encryptedEmail, {
            filename: `email-${senderEns}-${timestamp}.json`,
            metadata: {
              type: 'dmail-email',
              messageId: encryptedEmail.messageId,
            },
          })
        }

        // OPTIMIZATION: Use cached mailbox roots when available instead of re-resolving
        setStatusMessage('Preparing mailbox metadata...')
        let recipientMailboxRoot, senderMailboxRoot
        
        if (isSelfRecipient) {
          // Sending to self: Use cached mailbox root if available
          if (mailboxRootRef.current?.owner === senderEns) {
            recipientMailboxRoot = mailboxRootRef.current
            senderMailboxRoot = mailboxRootRef.current
            console.log('[sendEmail] Using cached mailbox root for self-send')
          } else {
            const mailboxRootRaw = await resolveMailboxRoot(senderEns, { provider: ensProvider })
            const normalized = normalizeMailboxRoot(mailboxRootRaw, { owner: senderEns })
            recipientMailboxRoot = normalized
            senderMailboxRoot = normalized
          }
        } else {
          // Different recipients: Resolve in parallel, using cache for sender
          const recipientPromise = resolveMailboxRoot(recipientEns, { provider: ensProvider })
          const senderPromise = mailboxRootRef.current?.owner === senderEns
            ? Promise.resolve(mailboxRootRef.current)
            : resolveMailboxRoot(senderEns, { provider: ensProvider })
          
          const [recipientRaw, senderRaw] = await Promise.all([recipientPromise, senderPromise])
          recipientMailboxRoot = normalizeMailboxRoot(recipientRaw, { owner: recipientEns })
          senderMailboxRoot = normalizeMailboxRoot(senderRaw, { owner: senderEns })
        }

        const toRecipients = [recipientEns]
        const ccRecipients = []
        const signatureMetadata = {
          messageId: encryptedEmail.messageId,
          bodyCid: recipientUpload?.cid ?? null,
          keyEnvelopesCid: recipientUpload?.cid ?? null,
          senderCopyCid: senderUpload?.cid ?? null,
          from: senderEns,
          to: toRecipients,
          cc: ccRecipients,
          timestamp,
          ephemeralPublicKey: encryptedEmail.recipientEnvelope?.ephemeralPublicKey ?? null,
        }
        if (!signatureMetadata.bodyCid || !signatureMetadata.keyEnvelopesCid) {
          throw new Error('Failed to compute signature metadata for this message. Try again.')
        }
        const metadataHash = computeEnvelopeMetadataHash(signatureMetadata)
        const signature = signEnvelope(activeIdentity.signingKey, metadataHash)

        const entryMetadata = {
          from: senderEns,
          to: recipientEns,
          toRecipients,
          cc: ccRecipients,
          timestamp,
          subjectPreview,
          messageId: encryptedEmail.messageId,
          attachments: attachmentSummaries,
          ephemeralPublicKey: encryptedEmail.recipientEnvelope?.ephemeralPublicKey ?? null,
          signature,
          signerPublicKey: activeIdentity.signingPublicKey,
          bodyCid: signatureMetadata.bodyCid,
          keyEnvelopesCid: signatureMetadata.keyEnvelopesCid,
          senderCopyCid: signatureMetadata.senderCopyCid,
        }

        // OPTIMIZATION: Parallelize mailbox updates when NOT sending to self
        let recipientMailboxUpdate, senderMailboxUpdate
        
        if (isSelfRecipient) {
          // Self-send: Must be sequential (sent needs updated inbox root)
          setStatusMessage('Appending to recipient mailbox...')
          recipientMailboxUpdate = await appendInboxEntry({
            ownerEns: recipientEns,
            mailboxRoot: recipientMailboxRoot,
            uploads: { recipient: recipientUpload, sender: senderUpload },
            metadata: entryMetadata,
            persistOptions: {
              metadataType: 'dmail-mailbox-inbox',
            },
            resolveOptions: { provider: ensProvider },
            resolverOptions: { provider: ensProvider },
          })
          
          console.log('[sendEmail] Inbox mailbox updated:', {
            newCid: recipientMailboxUpdate.uploadResult?.cid,
            mailboxRoot: recipientMailboxUpdate.mailboxRoot,
          })

          setStatusMessage('Appending to sender mailbox...')
          senderMailboxUpdate = await appendSentEntry({
            ownerEns: senderEns,
            mailboxRoot: recipientMailboxUpdate.mailboxRoot, // Use updated root from inbox append
            uploads: { recipient: recipientUpload, sender: senderUpload },
            metadata: { ...entryMetadata, folder: 'sent' },
            persistOptions: {
              metadataType: 'dmail-mailbox-sent',
            },
            resolveOptions: { provider: ensProvider },
            resolverOptions: { provider: ensProvider },
          })
        } else {
          // Different recipients: Can parallelize inbox and sent updates - saves ~5-10 seconds
          setStatusMessage('Appending to mailboxes (parallel)...')
          const [inbox, sent] = await Promise.all([
            appendInboxEntry({
              ownerEns: recipientEns,
              mailboxRoot: recipientMailboxRoot,
              uploads: { recipient: recipientUpload, sender: senderUpload },
              metadata: entryMetadata,
              persistOptions: {
                metadataType: 'dmail-mailbox-inbox',
              },
              resolveOptions: { provider: ensProvider },
              resolverOptions: { provider: ensProvider },
            }),
            appendSentEntry({
              ownerEns: senderEns,
              mailboxRoot: senderMailboxRoot,
              uploads: { recipient: recipientUpload, sender: senderUpload },
              metadata: { ...entryMetadata, folder: 'sent' },
              persistOptions: {
                metadataType: 'dmail-mailbox-sent',
              },
              resolveOptions: { provider: ensProvider },
              resolverOptions: { provider: ensProvider },
            })
          ])
          recipientMailboxUpdate = inbox
          senderMailboxUpdate = sent
        }
        
        console.log('[sendEmail] Sent mailbox updated:', {
          newCid: senderMailboxUpdate.uploadResult?.cid,
          mailboxRoot: senderMailboxUpdate.mailboxRoot,
        })

        // Update ENS mailbox pointer for the connected account to ensure refresh uses the new CID
        // Use setMailboxRootToEns to update BOTH inbox and sent pointers
        // OPTIMIZATION: Don't wait for blockchain confirmation (wait: false) - saves ~60+ seconds
        try {
          setStatusMessage('Updating ENS text records (inbox + sent)...')
          await setMailboxRootToEns(senderEns, senderMailboxUpdate.mailboxRoot, {
            provider: browserProvider,
            signer,
            wait: false, // Don't wait for blockchain confirmation - major time saver!
          })
          console.log('[sendEmail] ✓ ENS update initiated (not waiting for confirmation):', {
            inboxCid: senderMailboxUpdate.mailboxRoot?.inbox?.cid,
            sentCid: senderMailboxUpdate.mailboxRoot?.sent?.cid,
          })
        } catch (ensUpdateError) {
          console.warn('[sendEmail] Failed to update ENS mailbox pointers:', ensUpdateError)
        }

        // OPTIMIZATION: Use optimistic updates instead of full refresh - saves mailbox fetching time
        setStatusMessage('Email sent successfully!')
        
        // Update local state immediately with the new entry (optimistic update)
        const newEntry = senderMailboxUpdate.entry || {
          ...entryMetadata,
          cid: recipientUpload?.cid,
          _optimistic: true,
        }
        
        // Update both inbox and sent lists
        if (isSelfRecipient) {
          setMailboxEntries(prev => [newEntry, ...prev])
        }
        setSentEntries(prev => [newEntry, ...prev])
        setMailboxRoot(senderMailboxUpdate.mailboxRoot)
        
        // Clear compose form
        updateCompose({ to: '', subject: '', message: '', recipientPublicKey: '', attachments: [] })
        setPubKeyFetchError(null)
        setShowManualPubKey(false)
        setFetchingPubKey(false)
        setShowCompose(false)
      } catch (error) {
        console.error(error)
        setErrorMessage(error.message ?? 'Failed to send email')
      } finally {
        setSending(false)
      }
    },
    [
      composeState.attachments,
      composeState.message,
      composeState.recipientPublicKey,
      composeState.subject,
      composeState.to,
      ensureProvider,
      ensName,
      provider,
      refreshInbox,
      walletAddress,
      getEnsProvider,
      identityPublicKey,
      ensureIdentityMaterial,
    ]
  )

  const filteredEmails = useMemo(() => {
    const source = activeView === 'sent' ? sentEntries : mailboxEntries
    const sorted = [...source].sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0))
    if (!searchQuery) return sorted
    const query = searchQuery.toLowerCase()
    return sorted.filter(
      (entry) =>
        entry.from?.toLowerCase().includes(query) ||
        (Array.isArray(entry.toRecipients)
          ? entry.toRecipients.join(', ').toLowerCase().includes(query)
          : entry.to?.toLowerCase().includes(query)) ||
        entry.subjectPreview?.toLowerCase().includes(query)
    )
  }, [mailboxEntries, sentEntries, searchQuery, activeView])

  const formatTime = (timestamp) => {
    const date = new Date(timestamp)
    const now = new Date()
    const diff = now - date
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    
    if (days === 0) {
      return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })
    } else if (days < 7) {
      return date.toLocaleDateString('en-US', { weekday: 'short' })
    } else {
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    }
  }

  const getSignatureStatusClass = (status) => {
    if (status === true) return 'signature-valid'
    if (status === false) return 'signature-invalid'
    return 'signature-unsigned'
  }

  const getSignatureStatusIcon = (status) => {
    if (status === true) return '✓'
    if (status === false) return '⚠️'
    return '∙'
  }

  const getSignatureStatusTitle = (status) => {
    if (status === true) return 'Signature verified'
    if (status === false) return 'Signature invalid'
    return 'Unsigned message'
  }

  return (
    <div className="gmail-layout">
      {/* Header */}
      <header className="gmail-header">
        <div className="header-left">
          <button className="menu-btn" aria-label="Menu">☰</button>
          <h1 className="logo">
            <span className="logo-icon">📧</span>
            dMail
          </h1>
        </div>
        
        <div className="header-center">
          <div className="search-bar">
            <span className="search-icon">🔍</span>
            <input
              type="text"
              placeholder="Search mail"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        <div className="header-right">
          {walletAddress ? (
            <div className="wallet-status">
              <span className="wallet-indicator connected">●</span>
              <span className="user-info" title={walletAddress}>
                {ensName || `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`}
              </span>
              <button
                className="icon-btn disconnect-btn"
                onClick={handleDisconnectWallet}
                title="Disconnect Wallet"
              >
                ✖
              </button>
            </div>
          ) : (
            <>
              <button className="icon-btn" onClick={connectWallet} title="Connect Wallet">
                🔌
              </button>
              <span className="user-info">Not connected</span>
            </>
          )}
        </div>
      </header>

      {/* Status Messages - filter out wallet connection status since it's in navbar */}
      {statusMessage && statusMessage !== 'Wallet connected' && (
        <div className="toast toast-success">{statusMessage}</div>
      )}
      {errorMessage && <div className="toast toast-error">{errorMessage}</div>}

      <div className="gmail-container">
        {/* Sidebar */}
        <aside className={`gmail-sidebar ${calendarFullPage ? 'hidden' : ''}`}>
          <button
            className="compose-btn"
            onClick={() => setShowCompose(true)}
            disabled={!walletAddress}
          >
            <span className="compose-icon">✏️</span>
            Compose
          </button>

          <nav className="sidebar-nav">
            <button
              className={activeView === 'inbox' ? 'nav-item active' : 'nav-item'}
              onClick={() => {
                setActiveView('inbox')
                setSelectedEmails([])
              }}
            >
              <span className="nav-icon">📥</span>
              <span className="nav-label">Inbox</span>
              <span className="nav-count">{mailboxEntries.length}</span>
            </button>
            <button className="nav-item" onClick={() => alert('Not implemented')}>
              <span className="nav-icon">⭐</span>
              <span className="nav-label">Starred</span>
            </button>
            <button
              className={activeView === 'sent' ? 'nav-item active' : 'nav-item'}
              onClick={() => {
                setActiveView('sent')
                setSelectedEmails([])
              }}
            >
              <span className="nav-icon">📤</span>
              <span className="nav-label">Sent</span>
              <span className="nav-count">{sentEntries.length}</span>
            </button>
            <button className="nav-item" onClick={() => alert('Not implemented')}>
              <span className="nav-icon">📝</span>
              <span className="nav-label">Drafts</span>
            </button>
          </nav>

          <div className="sidebar-footer">
            <button className="text-btn" onClick={refreshInbox} disabled={!walletAddress || loadingInbox}>
              {loadingInbox ? '⏳ Loading...' : '🔄 Refresh'}
            </button>
            <div className="private-key-section">
              <label className="key-label">
                🔐 Identity (derived)
                <span className="key-hint" title="Derived from your wallet signature and registered via the resolver.">
                  ℹ️
                </span>
              </label>
              <input
                type="text"
                className="key-input"
                placeholder="Connect wallet to derive identity"
                value={identityPublicKey ?? ''}
                readOnly
              />
              {(identityDeriving || identityStatusMessage) && (
                <div className="key-help identity-status">
                  <small>
                    {identityDeriving
                      ? 'Generating dMail identity… approve MetaMask if prompted.'
                      : identityStatusMessage}
                  </small>
                </div>
              )}
              <button
                type="button"
                className="text-btn"
                onClick={handleRegenerateIdentity}
                disabled={!walletAddress || identityDeriving}
              >
                {identityDeriving ? 'Deriving identity…' : '♻️ Regenerate identity'}
              </button>
            </div>
          </div>
        </aside>

        {/* Email List */}
        <main className={`gmail-main ${calendarFullPage ? 'hidden' : ''}`}>
          <div className="toolbar">
            <div className="toolbar-left">
              <input 
                type="checkbox" 
                className="select-all" 
                checked={selectedEmails.length > 0 && selectedEmails.length === filteredEmails.length}
                onChange={toggleSelectAll}
                title="Select/Deselect all"
              />
              <button className="toolbar-btn" title="Refresh" onClick={refreshInbox}>
                ↻
              </button>
              {selectedEmails.length > 0 && (
                <button 
                  className="toolbar-btn delete-btn" 
                  title={`Delete ${selectedEmails.length} email(s)`} 
                  onClick={handleDeleteSelected}
                >
                  🗑️ Delete ({selectedEmails.length})
                </button>
              )}
            </div>
          </div>

          <div className="email-list">
            {loadingInbox ? (
              <div className="empty-state">Loading inbox...</div>
            ) : filteredEmails.length === 0 ? (
              <div className="empty-state">
                {searchQuery
                  ? 'No emails match your search'
                  : activeView === 'sent'
                  ? 'Your sent folder is empty'
                  : 'Your inbox is empty'}
              </div>
            ) : (
              filteredEmails.map((entry) => {
                const entryKey = entry.messageId ?? entry.cidSender ?? entry.cid
                const isActive = selectedEmail?.entry?.messageId
                  ? selectedEmail.entry.messageId === entry.messageId
                  : selectedEmail?.entry?.cid === entry.cid
                const isSelected = selectedEmails.some(e => (e.messageId ?? e.cid) === (entry.messageId ?? entry.cid))
                return (
                  <div
                    key={entryKey}
                    className={`email-item ${isActive ? 'active' : ''} ${isSelected ? 'selected' : ''}`}
                    onClick={() => openEmail(entry)}
                  >
                    <input 
                      type="checkbox" 
                      className="email-checkbox" 
                      checked={isSelected}
                      onChange={() => toggleEmailSelection(entry)}
                      onClick={(e) => e.stopPropagation()} 
                    />
                    <span className="email-star">☆</span>
                    <span className="email-sender">{entry.from || 'Unknown'}</span>
                    <span className="email-subject">
                      {entry.subjectPreview || '(No subject)'}
                      <span
                        className={`signature-badge ${getSignatureStatusClass(entry._signatureValid)}`}
                        title={getSignatureStatusTitle(entry._signatureValid)}
                      >
                        {getSignatureStatusIcon(entry._signatureValid)}
                      </span>
                    </span>
                    <span className="email-time">{formatTime(entry.timestamp)}</span>
                  </div>
                )
              })
            )}
          </div>
        </main>

        {/* Email Viewer */}
        <section className={`gmail-viewer ${selectedEmail && !calendarFullPage ? 'open' : ''}`}>
          {selectedEmail ? (
            <div className="email-detail">
              <div className="email-header">
                <h2 className="email-title">{selectedEmail.decrypted.subject}</h2>
                <div className="email-actions">
                  <button className="icon-btn" title="Reply">↩️</button>
                  <button className="icon-btn" title="Archive">🗄️</button>
                  <button className="icon-btn" title="Delete">🗑️</button>
                  <button className="icon-btn" onClick={() => setSelectedEmail(null)} title="Close">
                    ✕
                  </button>
                </div>
              </div>

              <div className="email-meta">
                <div className="sender-info">
                  <div className="sender-avatar">{selectedEmail.decrypted.from?.[0]?.toUpperCase() || '?'}</div>
                  <div className="sender-details">
                    <div className="sender-name">{selectedEmail.decrypted.from}</div>
                    <div className="sender-email">to {selectedEmail.decrypted.to}</div>
                    {Array.isArray(selectedEmail.entry?.cc) && selectedEmail.entry.cc.length > 0 && (
                      <div className="sender-email cc-line">cc {selectedEmail.entry.cc.join(', ')}</div>
                    )}
                  </div>
                </div>
                <div className="email-timestamp">
                  {new Date(selectedEmail.decrypted.timestamp).toLocaleString()}
                </div>
              </div>
              <div className="email-flags">
                {selectedEmail.entry?.folder === 'sent' && <span className="pill pill-sent">Sent</span>}
                {selectedEmail.entry?.signature && (
                  <span
                    className={`pill ${
                      selectedEmail.signatureValid === false
                        ? 'pill-error'
                        : selectedEmail.signatureValid
                        ? 'pill-success'
                        : 'pill-neutral'
                    }`}
                  >
                    {selectedEmail.signatureValid === false
                      ? '⚠️ Signature invalid'
                      : selectedEmail.signatureValid
                      ? '✓ Signature verified'
                      : 'Unsigned'}
                  </span>
                )}
              </div>

              <div className="email-body">
                <pre>{selectedEmail.decrypted.message}</pre>
              </div>

              {Array.isArray(selectedEmail.decrypted.attachments) &&
                selectedEmail.decrypted.attachments.length > 0 && (
                  <div className="email-attachments">
                    <div className="attachments-header">📎 {selectedEmail.decrypted.attachments.length} attachment(s)</div>
                    <div className="attachments-list">
                      {selectedEmail.decrypted.attachments.map((attachment, idx) => (
                        <div
                          key={idx}
                          className="attachment-item"
                          onClick={() => handleDownloadAttachment(attachment)}
                          title="Click to download"
                        >
                          <span className="attachment-icon">📄</span>
                          <span className="attachment-name">{attachment.filename}</span>
                          <span className="attachment-size">({attachment.mimeType})</span>
                          <span className="attachment-download">⬇</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
            </div>
          ) : (
            <div className="empty-viewer">
              <div className="empty-icon">📭</div>
              <p>Select an email to read</p>
            </div>
          )}
        </section>

        <CalendarSidebar
          events={calendarEvents}
          loading={calendarLoading}
          error={calendarError}
          onRefresh={refreshCalendar}
          onAddEvent={() => setShowEventModal(true)}
          onShareEvent={handleShareEvent}
          fullPage={calendarFullPage}
          onToggleFullPage={() => setCalendarFullPage(!calendarFullPage)}
        />
      </div>

      {/* Compose Modal */}
      {showCompose && (
        <div
          className="compose-modal-overlay"
          onClick={() => {
            setShowCompose(false)
            // Reset state when modal closes
            setPubKeyFetchError(null)
            setShowManualPubKey(false)
            setFetchingPubKey(false)
          }}
        >
          <div className="compose-modal" onClick={(e) => e.stopPropagation()}>
            <div className="compose-header">
              <h3>New Message</h3>
              <button
                className="close-btn"
                onClick={() => {
                  setShowCompose(false)
                  // Reset state when modal closes
                  setPubKeyFetchError(null)
                  setShowManualPubKey(false)
                  setFetchingPubKey(false)
                }}
              >
                ✕
              </button>
            </div>

            <form className="compose-form" onSubmit={handleSend}>
              <div className="compose-field">
                <input
                  type="text"
                  placeholder="To (ENS name, e.g. alice.eth)"
                  value={composeState.to}
                  onChange={(e) => {
                    const ensName = e.target.value.trim()
                    updateCompose({ to: ensName })
                    // Auto-fetch public key when ENS name is entered
                    if (ensName && ensName.endsWith('.eth')) {
                      fetchRecipientPublicKey(ensName)
                    } else {
                      setPubKeyFetchError(null)
                      setShowManualPubKey(false)
                      updateCompose({ recipientPublicKey: '' })
                    }
                  }}
                  onBlur={(e) => {
                    // Also try fetching on blur if not already fetched
                    const ensName = e.target.value.trim()
                    if (ensName && ensName.endsWith('.eth') && !composeState.recipientPublicKey) {
                      fetchRecipientPublicKey(ensName)
                    }
                  }}
                  required
                />
                {fetchingPubKey && (
                  <div className="field-status">🔍 Looking up public key from ENS...</div>
                )}
                {composeState.recipientPublicKey && !fetchingPubKey && !pubKeyFetchError && (
                  <div className="field-status success">✓ Public key found and loaded</div>
                )}
                {pubKeyFetchError && (
                  <div className="field-status error">{pubKeyFetchError}</div>
                )}
              </div>

              {(showManualPubKey || composeState.recipientPublicKey) && (
                <div className="compose-field">
                  <input
                    type="text"
                    placeholder="Recipient Public Key (optional override)"
                    value={composeState.recipientPublicKey}
                    onChange={(e) => {
                      updateCompose({ recipientPublicKey: e.target.value })
                      // If user manually enters a key, clear error
                      if (e.target.value) {
                        setPubKeyFetchError(null)
                      }
                    }}
                  />
                  <div className="field-help">
                    <small>
                      ℹ️ Only needed if ENS lookup failed. Usually auto-filled from {composeState.to || 'recipient'} ENS record.
                    </small>
                  </div>
                </div>
              )}

              <div className="compose-field">
                <input
                  type="text"
                  placeholder="Subject"
                  value={composeState.subject}
                  onChange={(e) => updateCompose({ subject: e.target.value })}
                  required
                />
              </div>

              <div className="compose-body">
                <textarea
                  placeholder="Message"
                  value={composeState.message}
                  onChange={(e) => updateCompose({ message: e.target.value })}
                  required
                />
              </div>

              {composeState.attachments.length > 0 && (
                <div className="compose-attachments">
                  {composeState.attachments.map((attachment, idx) => (
                    <div key={idx} className="compose-attachment">
                      📎 {attachment.filename}
                    </div>
                  ))}
                </div>
              )}

              <div className="compose-footer">
                <button type="submit" className="send-btn" disabled={sending}>
                  {sending ? '⏳ Sending...' : '📤 Send'}
        </button>
                <label className="attach-btn">
                  📎 Attach
                  <input type="file" multiple onChange={handleAttachments} style={{ display: 'none' }} />
                </label>
              </div>
            </form>
          </div>
        </div>
      )}

      {showEventModal && (
        <EventModal onClose={() => setShowEventModal(false)} onSave={handleSaveEvent} saving={savingEvent} />
      )}
      </div>
  )
}

async function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result
      if (typeof result === 'string') {
        const base64 = result.split(',').pop()
        resolve(base64 ?? '')
      } else {
        resolve('')
      }
    }
    reader.onerror = (error) => reject(error)
    reader.readAsDataURL(file)
  })
}

export default App
